import { EventEmitter } from "node:events";

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
