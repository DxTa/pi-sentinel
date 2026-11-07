import { EventEmitter } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { createSrtBackend, DEFAULT_SRT_HELPER_ENV } from "./srt-backend.js";
import type { SrtCommandSpec, SrtCommandSpecInput } from "../srt-command-spec.js";
import type { ResolvedSandboxProfile, SandboxConfig, UnmaskedPath } from "../types.js";

function makeConfig(): SandboxConfig {
  return {
    enabled: true,
    profiles: {},
    defaultProfile: "online-dev",
    roBinds: [],
    rwBinds: [],
  };
}

function makeProfile(name = "online-dev", network = true): ResolvedSandboxProfile {
  return {
    name,
    network,
    allowDocker: false,
    roBinds: [],
    rwBinds: [],
    env: { allow: [], deny: [] },
    maskedPaths: [],
  };
}

function makeSrtCommandSpec(command: string, unmaskedPaths: UnmaskedPath[] = []): SrtCommandSpec {
  return {
    command,
    cwd: "/repo",
    repoRoot: "/repo",
    profileName: "online-dev",
    networkEnabled: true,
    allowDocker: false,
    roBinds: [],
    rwBinds: [],
    maskedPaths: [],
    unmaskedPaths,
    secretEnvNames: [],
    envDenyPatterns: [],
    visibleReadPaths: [],
    runtimeReadAllowPaths: [],
    maskedShimPlan: { maskedFilePaths: [], maskedDenyPaths: [], shimCommands: [] },
    execShimPlan: {},
    networkPlan: {
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
    },
  };
}

function makeBackendWithSpawn(spawn: () => unknown) {
  return createSrtBackend({
    helperPath: () => "/helper.mjs",
    processExecPath: () => "/usr/bin/node",
    checkSrtStatus: () => ({
      available: true,
      platform: "darwin",
      packageAvailable: true,
      entrypointPath: "/helper.mjs",
      entrypointExists: true,
      dependencyChecks: [],
    }),
    buildSrtCommandSpecAsync: async ({ command }) => makeSrtCommandSpec(command),
    buildSrtRuntimeConfig: () => ({
      network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
      filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
    }),
    loadSpawn: async () => ({ spawn: spawn as never }),
  });
}

describe("createSrtBackend", () => {
  it("blocks before spawn when dotenv values cannot be loaded for masking", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "pi-srt-mask-failure-"));
    const spawn = vi.fn();
    const backend = makeBackendWithSpawn(spawn);
    const onData = vi.fn();

    try {
      const result = await backend.createBashOperations({
        sandboxConfig: makeConfig(),
        cwd: "/repo",
        preResolvedProfile: makeProfile(),
        forceSrt: true,
        outputMasking: { dotenvPaths: [path.join(directory, "missing.env")] },
      } as never).exec("cat .env", "/repo", { onData } as never);

      expect(result).toEqual({ exitCode: 1 });
      expect(spawn).not.toHaveBeenCalled();
      expect(String(onData.mock.calls[0]?.[0])).toContain("command blocked");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("masks dotenv values before streaming user Bash output", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "pi-srt-output-mask-"));
    const dotenvPath = path.join(directory, ".env");
    await writeFile(dotenvPath, "API_TOKEN=VALUE-123456\n", "utf8");

    const child = Object.assign(new EventEmitter(), {
      stdout: new EventEmitter(),
      stderr: new EventEmitter(),
      kill: vi.fn(),
    });
    let resolveSpawn!: () => void;
    const spawned = new Promise<void>((resolve) => { resolveSpawn = resolve; });
    const backend = makeBackendWithSpawn(() => {
      resolveSpawn();
      return child;
    });
    const onData = vi.fn();
    const execution = backend.createBashOperations({
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
      forceSrt: true,
      outputMasking: { dotenvPaths: [dotenvPath] },
    } as never).exec("cat .env", "/repo", { onData } as never);

    try {
      const didSpawn = await Promise.race([spawned.then(() => true), execution.then(() => false)]);
      expect(didSpawn, String(onData.mock.calls[0]?.[0] ?? "")).toBe(true);
      child.stdout.emit("data", Buffer.from("prefix VALUE-"));
      child.stdout.emit("data", Buffer.from("123456 suffix\n"));
      expect(onData).not.toHaveBeenCalled();

      child.emit("close", 0);
      await expect(execution).resolves.toEqual({ exitCode: 0 });
      const output = Buffer.concat(onData.mock.calls.map(([data]) => data as Buffer)).toString("utf8");
      expect(output).toContain("prefix **** suffix");
      expect(output).not.toContain("VALUE-123456");
    } finally {
      child.emit("close", 0);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("fully redacts protected-path output before streaming user Bash results", async () => {
    const child = Object.assign(new EventEmitter(), {
      stdout: new EventEmitter(),
      stderr: new EventEmitter(),
      kill: vi.fn(),
    });
    let resolveSpawn!: () => void;
    const spawned = new Promise<void>((resolve) => { resolveSpawn = resolve; });
    const backend = makeBackendWithSpawn(() => {
      resolveSpawn();
      return child;
    });
    const onData = vi.fn();
    const execution = backend.createBashOperations({
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
      forceSrt: true,
      outputMasking: { redactOutput: true },
    } as never).exec("cat ~/.ssh/id_ed25519", "/repo", { onData } as never);

    const didSpawn = await Promise.race([spawned.then(() => true), execution.then(() => false)]);
    expect(didSpawn, String(onData.mock.calls[0]?.[0] ?? "")).toBe(true);
    child.stdout.emit("data", Buffer.from("SYNTHETIC-KEY-DATA"));
    child.emit("close", 0);
    await expect(execution).resolves.toEqual({ exitCode: 0 });

    const output = Buffer.concat(onData.mock.calls.map(([data]) => data as Buffer)).toString("utf8");
    expect(output).toBe("****");
    expect(output).not.toContain("SYNTHETIC-KEY-DATA");
  });

  it("fails closed when SRT status is unavailable", async () => {
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      checkSrtStatus: () => ({
        available: false,
        platform: "darwin",
        packageAvailable: false,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
        error: "missing srt",
      }),
      packageAvailable: () => false,
    });

    await expect(backend.wrapCommand({
      command: "git status",
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    })).resolves.toEqual({ block: true, reason: "missing srt" });
  });

  it("fails closed when wrap preparation exceeds its filesystem budget", async () => {
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpecAsync: async () => {
        throw new Error("Sandbox filesystem preparation exceeded 2000 ms");
      },
    });

    await expect(backend.wrapCommand({
      command: "printf ok",
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    })).resolves.toEqual({
      block: true,
      reason: "Sandbox filesystem preparation exceeded 2000 ms",
    });
  });

  it("builds helper shell command when available", async () => {
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpec: () => ({
        command: "git status",
        cwd: "/repo",
        repoRoot: "/repo",
        profileName: "online-dev",
        networkEnabled: true,
        allowDocker: false,
        roBinds: [],
        rwBinds: [],
        maskedPaths: [],
        unmaskedPaths: [],
        secretEnvNames: [],
        envDenyPatterns: [],
        networkPlan: {
          mode: "runtime-filtered",
          requiresOuterPrompt: false,
          unmatchedHostAction: "deny",
          config: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        },
      }),
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
    });

    const result = await backend.wrapCommand({
      command: "git status",
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    });

    expect(result && "command" in result && result.command.includes(DEFAULT_SRT_HELPER_ENV)).toBe(true);
    expect(result && "command" in result && result.command.includes("/usr/bin/node")).toBe(true);
    expect(result && "command" in result && result.command.includes("/helper.mjs")).toBe(true);
  });

  it.each([
    { platform: "linux", rg: "/pkg/bin/rg", expected: { command: "/pkg/bin/rg" } },
    { platform: "linux", rg: "rg", expected: undefined },
    { platform: "darwin", rg: "/pkg/bin/rg", expected: undefined },
  ])("passes the bundled ripgrep to SRT only on Linux ($platform, $rg)", async ({ platform, rg, expected }) => {
    const statusInputs: Array<{ ripgrepCommand?: string }> = [];
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      platform: () => platform,
      ripgrepCommand: () => rg,
      checkSrtStatus: (input) => {
        statusInputs.push(input);
        return {
          available: true,
          platform,
          packageAvailable: true,
          entrypointPath: "/helper.mjs",
          entrypointExists: true,
          dependencyChecks: [],
        };
      },
      buildSrtCommandSpec: ({ command }) => makeSrtCommandSpec(command),
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
    });

    const result = await backend.wrapCommand({
      command: "git status",
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    });

    expect(statusInputs[0]?.ripgrepCommand).toBe(rg);
    const encoded = result && "command" in result
      ? new RegExp(`${DEFAULT_SRT_HELPER_ENV}='?([A-Za-z0-9+/=]+)`).exec(result.command)?.[1]
      : undefined;
    expect(encoded).toBeDefined();
    expect(JSON.parse(Buffer.from(String(encoded), "base64").toString("utf8")).runtimeConfig.ripgrep).toEqual(expected);
  });

  it("spills oversized wrapper payload to a private file", async () => {
    const command = "x".repeat(100_000);
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpec: ({ command, cwd, repoRoot }) => ({
        command,
        cwd,
        repoRoot: repoRoot ?? cwd,
        profileName: "online-dev",
        networkEnabled: true,
        allowDocker: false,
        roBinds: [],
        rwBinds: [],
        maskedPaths: [],
        unmaskedPaths: [],
        secretEnvNames: [],
        envDenyPatterns: [],
        networkPlan: {
          mode: "runtime-filtered",
          requiresOuterPrompt: false,
          unmatchedHostAction: "deny",
          config: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        },
      }),
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
    });

    const result = await backend.wrapCommand({
      command,
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    });

    expect(result && "command" in result ? result.command.length : 0).toBeLessThan(2_000);
    expect(result && "command" in result && result.command).toContain("PI_SRT_HELPER_INPUT_FILE=");
    expect(result && "command" in result && result.command).toContain(`${DEFAULT_SRT_HELPER_ENV}=''`);

    const wrapped = result as { command: string; cleanup?: () => void };
    const match = wrapped.command.match(/PI_SRT_HELPER_INPUT_FILE=(?:'([^']+)'|([^\s]+))/);
    const file = match?.[1] ?? match?.[2];
    expect(file).toBeDefined();
    expect(JSON.parse(readFileSync(file!, "utf8")).command).toBe(command);
    expect(wrapped.cleanup).toBeTypeOf("function");
    await wrapped.cleanup?.();
    expect(existsSync(file!)).toBe(false);
  });

  it("uses and cleans helper input file for direct helper spawn", async () => {
    const command = "x".repeat(100_000);
    const stdout = new EventEmitter();
    const stderr = new EventEmitter();
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      kill: () => void;
    };
    child.stdout = stdout;
    child.stderr = stderr;
    child.kill = vi.fn();
    let payloadFile = "";
    const spawn = vi.fn((_executable: string, _args: string[], options: { env: NodeJS.ProcessEnv }) => {
      payloadFile = options.env.PI_SRT_HELPER_INPUT_FILE ?? "";
      expect(payloadFile).not.toBe("");
      expect(options.env[DEFAULT_SRT_HELPER_ENV]).toBeUndefined();
      expect(JSON.parse(readFileSync(payloadFile, "utf8")).command).toBe(command);
      process.nextTick(() => child.emit("close", 0));
      return child as never;
    });
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpec: ({ command, cwd, repoRoot }) => ({
        command,
        cwd,
        repoRoot: repoRoot ?? cwd,
        profileName: "online-dev",
        networkEnabled: true,
        allowDocker: false,
        roBinds: [],
        rwBinds: [],
        maskedPaths: [],
        unmaskedPaths: [],
        secretEnvNames: [],
        envDenyPatterns: [],
        networkPlan: {
          mode: "runtime-filtered",
          requiresOuterPrompt: false,
          unmatchedHostAction: "deny",
          config: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        },
      }),
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
      loadSpawn: async () => ({ spawn: spawn as never }),
    });

    const result = await backend.createBashOperations({
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    }).exec(command, "/repo", { env: { FOO: "bar" }, onData: vi.fn() } as never);

    expect(result).toEqual({ exitCode: 0 });
    expect(existsSync(payloadFile)).toBe(false);
  });

  it("fails closed without spawning when command preparation fails", async () => {
    const spawn = vi.fn();
    const onData = vi.fn();
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpecAsync: async () => {
        throw new Error("Masked file scan failed for /repo: scan duration budget exceeded");
      },
      loadSpawn: async () => ({ spawn: spawn as never }),
    });

    const result = await backend.createBashOperations({
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    }).exec("git status", "/repo", { onData } as never);

    expect(result).toEqual({ exitCode: 1 });
    expect(String(onData.mock.calls[0]?.[0])).toContain("scan duration budget exceeded");
    expect(spawn).not.toHaveBeenCalled();
  });

  it("spawns helper process for bash operations", async () => {
    const stdout = new EventEmitter();
    const stderr = new EventEmitter();
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      kill: () => void;
    };
    child.stdout = stdout;
    child.stderr = stderr;
    child.kill = vi.fn();

    const spawn = vi.fn(() => {
      process.nextTick(() => child.emit("close", 0));
      return child as never;
    });

    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpecAsync: async () => ({
        command: "git status",
        cwd: "/repo",
        repoRoot: "/repo",
        profileName: "online-dev",
        networkEnabled: true,
        allowDocker: false,
        roBinds: [],
        rwBinds: [],
        maskedPaths: [],
        unmaskedPaths: [],
        secretEnvNames: [],
        envDenyPatterns: [],
        networkPlan: {
          mode: "runtime-filtered",
          requiresOuterPrompt: false,
          unmatchedHostAction: "deny",
          config: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        },
      }),
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
      loadSpawn: async () => ({ spawn: spawn as never }),
    });

    const result = await backend.createBashOperations({
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    }).exec("git status", "/repo", { env: { FOO: "bar" }, onData: vi.fn() } as never);

    expect(spawn).toHaveBeenCalledWith(
      "/usr/bin/node",
      ["/helper.mjs"],
      expect.objectContaining({
        cwd: "/repo",
        env: expect.objectContaining({ FOO: "bar", [DEFAULT_SRT_HELPER_ENV]: expect.any(String) }),
        signal: undefined,
      }),
    );
    const helperEnv = spawn.mock.calls[0]?.[2]?.env?.[DEFAULT_SRT_HELPER_ENV];
    const decoded = JSON.parse(Buffer.from(String(helperEnv), "base64").toString("utf8"));
    expect(decoded.unmatchedHostAction).toBe("deny");
    expect(result).toEqual({ exitCode: 0 });
  });

  it.each([
    { failureMode: "asynchronous", throwsSynchronously: false },
    { failureMode: "synchronous", throwsSynchronously: true },
  ])("reports only E2BIG size metadata for helper spawn failures ($failureMode)", async ({ throwsSynchronously }) => {
    const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter; kill: () => void };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = vi.fn();
    const error = Object.assign(new Error("spawn E2BIG"), { code: "E2BIG" });
    const spawn = vi.fn(() => {
      if (throwsSynchronously) throw error;
      process.nextTick(() => child.emit("error", error));
      return child as never;
    });
    const report = vi.fn();
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpecAsync: async () => ({
        command: "git status",
        cwd: "/repo",
        repoRoot: "/repo",
        profileName: "online-dev",
        networkEnabled: true,
        allowDocker: false,
        roBinds: [],
        rwBinds: [],
        maskedPaths: [],
        unmaskedPaths: [],
        secretEnvNames: [],
        envDenyPatterns: [],
        networkPlan: {
          mode: "runtime-filtered",
          requiresOuterPrompt: false,
          unmatchedHostAction: "deny",
          config: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        },
      }),
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
      loadSpawn: async () => ({ spawn: spawn as never }),
      onE2Big: report,
    });

    const execution = backend.createBashOperations({
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    }).exec("git status", "/repo", {
      env: { TOKEN_VALUE: "do-not-log-this-value" },
      onData: vi.fn(),
    } as never);

    if (throwsSynchronously) {
      await expect(execution).rejects.toMatchObject({ code: "E2BIG" });
    } else {
      await expect(execution).resolves.toEqual({ exitCode: 1 });
    }
    expect(report).toHaveBeenCalledTimes(1);
    const diagnostic = report.mock.calls[0]?.[0] as Record<string, unknown>;
    const spawnEnv = (spawn.mock.calls[0]?.[2] as { env: NodeJS.ProcessEnv }).env;
    const payload = String(spawnEnv[DEFAULT_SRT_HELPER_ENV]);
    const expectedEnvBytes = Object.entries(spawnEnv).reduce(
      (total, [name, value]) => total + (typeof value === "string" ? Buffer.byteLength(`${name}=${value}\0`, "utf8") : 0),
      0,
    );
    expect(diagnostic).toMatchObject({
      route: "srt-helper",
      errorCode: "E2BIG",
      commandBytes: Buffer.byteLength("git status", "utf8"),
      helperPayloadBytes: Buffer.byteLength(Buffer.from(payload, "base64").toString("utf8"), "utf8"),
      spawnEnvironment: {
        totalBytes: expectedEnvBytes,
        largestVariables: expect.arrayContaining([
          { name: DEFAULT_SRT_HELPER_ENV, bytes: Buffer.byteLength(`${DEFAULT_SRT_HELPER_ENV}=${payload}\0`, "utf8") },
        ]),
      },
    });
    expect(JSON.stringify(diagnostic)).not.toContain("do-not-log-this-value");
    expect(JSON.stringify(diagnostic)).not.toContain("git status");
    expect(JSON.stringify(diagnostic)).not.toContain(payload);
  });

  it("reports E2BIG size metadata when bypass spawn throws synchronously", async () => {
    const error = Object.assign(new Error("spawn E2BIG"), { code: "E2BIG" });
    const spawn = vi.fn(() => { throw error; });
    const report = vi.fn();
    const backend = createSrtBackend({
      loadSpawn: async () => ({ spawn: spawn as never }),
      onE2Big: report,
    });
    const command = "git push origin main";
    const env = { TOKEN_VALUE: "do-not-log-this-value" };
    const execution = backend.createBashOperations({
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    }).exec(command, "/repo", { env, onData: vi.fn() } as never);

    await expect(execution).rejects.toMatchObject({ code: "E2BIG" });

    expect(report).toHaveBeenCalledTimes(1);
    const diagnostic = report.mock.calls[0]?.[0] as Record<string, unknown>;
    const spawnEnv = (spawn.mock.calls[0]?.[2] as { env: NodeJS.ProcessEnv }).env;
    const expectedEnvBytes = Object.entries(spawnEnv).reduce(
      (total, [name, value]) => total + (typeof value === "string" ? Buffer.byteLength(`${name}=${value}\0`, "utf8") : 0),
      0,
    );
    expect(diagnostic).toMatchObject({
      route: "srt-bypass",
      errorCode: "E2BIG",
      commandBytes: Buffer.byteLength(command, "utf8"),
      spawnEnvironment: { totalBytes: expectedEnvBytes },
    });
    expect(JSON.stringify(diagnostic)).not.toContain("do-not-log-this-value");
    expect(JSON.stringify(diagnostic)).not.toContain(command);
  });

  it("passes the configured CA path to the helper only when enabled", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "pi-srt-ca-input-"));
    const file = path.join(dir, "ca.pem");
    const previous = process.env.SSL_CERT_FILE;
    await writeFile(file, "certificate");
    process.env.SSL_CERT_FILE = file;
    try {
      const backend = createSrtBackend({
        helperPath: () => "/helper.mjs",
        processExecPath: () => "/usr/bin/node",
        checkSrtStatus: () => ({ available: true, platform: "darwin", packageAvailable: true, entrypointPath: "/helper.mjs", entrypointExists: true, dependencyChecks: [] }),
        buildSrtCommandSpec: ({ command }) => makeSrtCommandSpec(command),
        buildSrtRuntimeConfig: () => ({ filesystem: { allowRead: [], allowWrite: [], denyRead: [], denyWrite: [] } }),
      });
      const makeInput = (trustCaBundle: boolean) => ({
        command: "npm install", sandboxConfig: makeConfig(), cwd: "/repo", preResolvedProfile: makeProfile(), trustCaBundle,
      });
      const decode = async (enabled: boolean) => {
        const result = await backend.wrapCommand(makeInput(enabled));
        if (!result || !("command" in result)) throw new Error("Expected SRT command");
        const encoded = new RegExp(`${DEFAULT_SRT_HELPER_ENV}='?([A-Za-z0-9+/=]+)`).exec(result.command)?.[1];
        return JSON.parse(Buffer.from(String(encoded), "base64").toString("utf8"));
      };
      expect((await decode(false)).trustedCa).toBeUndefined();
      expect((await decode(true)).trustedCa).toEqual({ value: file, path: expect.any(String) });
    } finally {
      if (previous === undefined) delete process.env.SSL_CERT_FILE;
      else process.env.SSL_CERT_FILE = previous;
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("keeps forced resource-backed Git commands inside SRT wrapping", async () => {
    const command = "git push git@example.invalid:org/repo.git";
    const unmaskedPaths = [{ path: "/tmp/synthetic-ssh/id_ed25519", writable: false }];
    const buildSrtCommandSpec = vi.fn((input: SrtCommandSpecInput) =>
      makeSrtCommandSpec(input.command, input.unmaskedPaths),
    );
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      checkSrtStatus: () => ({
        available: true,
        platform: "linux",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpec,
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
    });

    const result = await backend.wrapCommand({
      command,
      sandboxConfig: { ...makeConfig(), bypassCommands: [] },
      cwd: "/repo",
      unmaskedPaths,
      preResolvedProfile: makeProfile(),
      forceSrt: true,
    });

    expect(result).toHaveProperty("command");
    expect(result).not.toEqual({ command });
    expect(buildSrtCommandSpec).toHaveBeenCalledWith(expect.objectContaining({ unmaskedPaths }));
  });

  it("keeps forced resource-backed Git user bash inside SRT operations", async () => {
    const command = "git push git@example.invalid:org/repo.git";
    const unmaskedPaths = [{ path: "/tmp/synthetic-ssh/id_ed25519", writable: false }];
    const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter; kill: () => void };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = vi.fn();
    const spawn = vi.fn(() => {
      process.nextTick(() => child.emit("close", 0));
      return child as never;
    });
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      processExecPath: () => "/usr/bin/node",
      checkSrtStatus: () => ({
        available: true,
        platform: "linux",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
      buildSrtCommandSpec: ({ command, unmaskedPaths }) => makeSrtCommandSpec(command, unmaskedPaths),
      buildSrtRuntimeConfig: () => ({
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
        filesystem: { allowRead: ["/repo"], allowWrite: ["/repo"], denyRead: [], denyWrite: [] },
      }),
      loadSpawn: async () => ({ spawn: spawn as never }),
    });

    const result = await backend.createBashOperations({
      sandboxConfig: { ...makeConfig(), bypassCommands: [] },
      cwd: "/repo",
      unmaskedPaths,
      preResolvedProfile: makeProfile(),
      forceSrt: true,
    }).exec(command, "/repo", { env: {}, onData: vi.fn() } as never);

    expect(result).toEqual({ exitCode: 0 });
    expect(spawn).toHaveBeenCalledWith(
      "/usr/bin/node",
      ["/helper.mjs"],
      expect.objectContaining({ env: expect.objectContaining({ [DEFAULT_SRT_HELPER_ENV]: expect.any(String) }) }),
    );
    const spawnOptions = spawn.mock.calls[0]?.[2] as { env: NodeJS.ProcessEnv };
    const encoded = spawnOptions.env[DEFAULT_SRT_HELPER_ENV];
    expect(JSON.parse(Buffer.from(String(encoded), "base64").toString("utf8")).unmaskedPaths).toEqual(unmaskedPaths);
  });

  it("bypasses built-in git transport commands without SRT wrapping", async () => {
    const backend = createSrtBackend({
      helperPath: () => "/helper.mjs",
      checkSrtStatus: () => ({
        available: true,
        platform: "darwin",
        packageAvailable: true,
        entrypointPath: "/helper.mjs",
        entrypointExists: true,
        dependencyChecks: [],
      }),
    });

    await expect(backend.wrapCommand({
      command: "git push origin main",
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile(),
    })).resolves.toEqual({ command: "git push origin main" });
  });

});
