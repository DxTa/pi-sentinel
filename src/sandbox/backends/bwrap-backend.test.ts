import { EventEmitter } from "node:events";

import { describe, expect, it, vi } from "vitest";

import { createBwrapBackend } from "./bwrap-backend.js";
import type { ResolvedSandboxProfile, SandboxConfig } from "../types.js";

function makeConfig(): SandboxConfig {
  return {
    enabled: true,
    profiles: {},
    defaultProfile: "offline-dev",
    roBinds: [],
    rwBinds: [],
    runnerPath: null,
  };
}

function makeProfile(name = "offline-dev", network = false): ResolvedSandboxProfile {
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

describe("createBwrapBackend", () => {
  it("fails closed when sandbox status is unavailable", () => {
    const backend = createBwrapBackend({
      checkSandboxStatus: () => ({
        available: false,
        bwrapBinary: false,
        bwrapVersion: null,
        runnerPath: null,
        runnerExists: false,
        error: "missing bwrap",
      }),
    });

    expect(
      backend.wrapCommand({
        command: "git status",
        sandboxConfig: makeConfig(),
        cwd: "/repo",
      }),
    ).toEqual({ block: true, reason: "missing bwrap" });
  });

  it("shell-quotes wrapped command arguments safely", () => {
    const backend = createBwrapBackend({
      checkSandboxStatus: () => ({
        available: true,
        bwrapBinary: true,
        bwrapVersion: "1.0",
        runnerPath: "/runner",
        runnerExists: true,
      }),
      extractAllNetworkTargets: () => [],
      resolveSandboxProfile: () => makeProfile(),
      buildBwrapCommand: () => ({
        command: ["/runner", "bash", "-lc", "cd /repo && git status"],
        effectiveCwd: null,
      }),
    });

    expect(
      backend.wrapCommand({
        command: "cd /repo && git status",
        sandboxConfig: makeConfig(),
        cwd: "/repo",
      }),
    ).toEqual({
      command: "/runner bash -lc 'cd /repo && git status'",
    });
  });

  it("spawns built runner argv for bash operations", async () => {
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

    const backend = createBwrapBackend({
      extractAllNetworkTargets: () => [],
      resolveSandboxProfile: () => makeProfile(),
      buildBwrapCommand: () => ({
        command: ["/runner", "--cwd", "/repo", "--", "bash", "-lc", "git status"],
        effectiveCwd: null,
      }),
      loadSpawn: async () => ({ spawn: spawn as never }),
    });

    const result = await backend
      .createBashOperations({ sandboxConfig: makeConfig(), cwd: "/repo" })
      .exec("git status", "/repo", { env: { FOO: "bar" }, onData: vi.fn() } as never);

    expect(spawn).toHaveBeenCalledWith(
      "/runner",
      ["--cwd", "/repo", "--", "bash", "-lc", "git status"],
      {
        cwd: "/repo",
        env: { FOO: "bar" },
        signal: undefined,
      },
    );
    expect(result).toEqual({ exitCode: 0 });
  });
});
