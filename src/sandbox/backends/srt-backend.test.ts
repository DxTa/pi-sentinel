import { EventEmitter } from "node:events";
import { existsSync, readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import { createSrtBackend, DEFAULT_SRT_HELPER_ENV } from "./srt-backend.js";
import type { ResolvedSandboxProfile, SandboxConfig } from "../types.js";

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

describe("createSrtBackend", () => {
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
