import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { checkSrtStatus, helperRuntimePath } from "./srt-status.js";

describe("checkSrtStatus", () => {
  it("fails closed when SRT package is unavailable", () => {
    expect(
      checkSrtStatus({
        platform: "darwin",
        entrypointPath: "/tmp/sandbox-run.sh",
        hasEntrypoint: true,
        packageAvailable: false,
        commandAvailable: () => false,
      }),
    ).toEqual({
      available: false,
      platform: "darwin",
      packageAvailable: false,
      entrypointPath: "/tmp/sandbox-run.sh",
      entrypointExists: true,
      dependencyChecks: [],
      error: "@anthropic-ai/sandbox-runtime package not available to runner.",
    });
  });

  it("requires Linux runtime dependencies when platform is linux", () => {
    expect(
      checkSrtStatus({
        platform: "linux",
        entrypointPath: "/tmp/sandbox-run.sh",
        hasEntrypoint: true,
        packageAvailable: true,
        commandAvailable: (command) => command === "bwrap",
      }),
    ).toEqual({
      available: false,
      platform: "linux",
      packageAvailable: true,
      entrypointPath: "/tmp/sandbox-run.sh",
      entrypointExists: true,
      dependencyChecks: [
        { name: "rg", available: false },
        { name: "bwrap", available: true },
        { name: "socat", available: false },
      ],
      error: "Missing SRT runtime dependencies: rg, socat.",
    });
  });

  it("fails closed on unsupported platforms even when package is present", () => {
    expect(
      checkSrtStatus({
        platform: "win32",
        entrypointPath: "/tmp/sandbox-run.sh",
        hasEntrypoint: true,
        packageAvailable: true,
        commandAvailable: () => true,
      }),
    ).toEqual({
      available: false,
      platform: "win32",
      packageAvailable: true,
      entrypointPath: "/tmp/sandbox-run.sh",
      entrypointExists: true,
      dependencyChecks: [],
      error: "SRT sandbox not supported on win32.",
    });
  });

  it("does not require extra runtime commands on macOS", () => {
    expect(
      checkSrtStatus({
        platform: "darwin",
        entrypointPath: "/tmp/sandbox-run.sh",
        hasEntrypoint: true,
        packageAvailable: true,
        commandAvailable: () => false,
      }),
    ).toEqual({
      available: true,
      platform: "darwin",
      packageAvailable: true,
      entrypointPath: "/tmp/sandbox-run.sh",
      entrypointExists: true,
      dependencyChecks: [],
    });
  });

  it("reports available when package, entrypoint, and platform deps exist", () => {
    expect(
      checkSrtStatus({
        platform: "linux",
        entrypointPath: "/tmp/sandbox-run.sh",
        hasEntrypoint: true,
        packageAvailable: true,
        commandAvailable: () => true,
      }),
    ).toEqual({
      available: true,
      platform: "linux",
      packageAvailable: true,
      entrypointPath: "/tmp/sandbox-run.sh",
      entrypointExists: true,
      dependencyChecks: [
        { name: "rg", available: true },
        { name: "bwrap", available: true },
        { name: "socat", available: true },
      ],
    });
  });

  it("checks the configured ripgrep command instead of rg on PATH", () => {
    const checked: string[] = [];
    const status = checkSrtStatus({
      platform: "linux",
      entrypointPath: "/tmp/sandbox-run.sh",
      hasEntrypoint: true,
      packageAvailable: true,
      commandAvailable: (command) => {
        checked.push(command);
        return command !== "rg";
      },
      ripgrepCommand: "/pkg/bin/rg",
    });
    expect(status.available).toBe(true);
    expect(checked).toEqual(["/pkg/bin/rg", "bwrap", "socat"]);
  });

  it("fails when configured entrypoint is missing even if package is present", () => {
    expect(
      checkSrtStatus({
        platform: "darwin",
        entrypointPath: "/tmp/sandbox-run.sh",
        hasEntrypoint: false,
        packageAvailable: true,
        commandAvailable: () => true,
      }),
    ).toEqual({
      available: false,
      platform: "darwin",
      packageAvailable: true,
      entrypointPath: "/tmp/sandbox-run.sh",
      entrypointExists: false,
      dependencyChecks: [],
      error: "SRT entrypoint not found at /tmp/sandbox-run.sh.",
    });
  });
});

describe("helperRuntimePath", () => {
  it.each(["/usr/local/bin/node", "/opt/homebrew/bin/node", "/usr/local/bin/bun", "C:\\Program Files\\nodejs\\node.exe"])(
    "keeps a real Node or Bun runtime: %s",
    (execPath) => {
      expect(helperRuntimePath(execPath, "/nowhere")).toBe(execPath);
    },
  );

  it("replaces a compiled host binary with node from PATH", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "pi-helper-runtime-"));
    const fakeNode = path.join(dir, "node");
    writeFileSync(fakeNode, "");
    try {
      expect(helperRuntimePath("/Users/me/.pi-bolt/pi-bolt", `/nonexistent${path.delimiter}${dir}`)).toBe(fakeNode);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("falls back to bare node when PATH has none", () => {
    expect(helperRuntimePath("/Users/me/.pi-bolt/pi-bolt", "/nonexistent")).toBe("node");
  });
});
