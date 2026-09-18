import { afterEach, describe, expect, it, vi } from "vitest";

import { buildSrtRuntimeConfig } from "./srt-runtime-config.js";
import type { SrtCommandSpec } from "./srt-command-spec.js";
import * as dockerSocket from "./docker-socket.js";

function makeSpec(overrides: Partial<SrtCommandSpec> = {}): SrtCommandSpec {
  return {
    command: "git status",
    cwd: "/repo/app",
    repoRoot: "/repo",
    profileName: "online-dev",
    networkEnabled: true,
    allowDocker: false,
    roBinds: ["/shared-ro"],
    rwBinds: ["/shared-rw"],
    maskedPaths: [],
    unmaskedPaths: [],
    secretEnvNames: [],
    envDenyPatterns: [],
    visibleReadPaths: ["/repo", "/repo/app", "/shared-ro", "/shared-rw", "/usr", "/bin", "/Users/me"],
    runtimeReadAllowPaths: ["/repo", "/repo/app", "/shared-ro", "/shared-rw", "/usr", "/bin"],
    maskedShimPlan: { maskedFilePaths: [], maskedDenyPaths: [], shimCommands: [] },
    networkPlan: {
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: ["github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
      },
    },
    ...overrides,
  };
}

describe("buildSrtRuntimeConfig", () => {
  afterEach(() => vi.restoreAllMocks());
  it("translates command spec into filesystem and network config", () => {
    expect(buildSrtRuntimeConfig(makeSpec())).toEqual({
      network: {
        allowedDomains: ["github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
        allowAllUnixSockets: true,
      },
      filesystem: {
        allowRead: ["/repo", "/repo/app", "/shared-ro", "/shared-rw", "/usr", "/bin"],
        allowWrite: ["/repo", "/repo/app", "/shared-rw"],
        denyRead: ["/"],
        denyWrite: [],
      },
    });
  });

  it("denies concrete masked reads while allowing shim placeholder UX", () => {
    expect(
      buildSrtRuntimeConfig(
        makeSpec({
          maskedPaths: ["**/.env"],
          maskedShimPlan: { maskedFilePaths: ["/repo/app/.env"], maskedDenyPaths: ["/repo/app/.env"], shimCommands: ["cat"] },
        }),
      ).filesystem,
    ).toEqual(expect.objectContaining({
      denyRead: ["/", "/repo/app/.env"],
      denyWrite: ["/repo/app/.env"],
    }));
  });

  it("allows approved read-only unmasked paths under SRT while keeping them denied for write", () => {
    const filesystem = buildSrtRuntimeConfig(
      makeSpec({
        unmaskedPaths: [{ path: "/repo/.env", writable: false }],
        maskedShimPlan: { maskedFilePaths: [], maskedDenyPaths: ["/repo/.env"], shimCommands: [] },
      }),
    ).filesystem;

    expect(filesystem.allowRead).toEqual(expect.arrayContaining(["/repo/.env"]));
    expect(filesystem.allowWrite).not.toContain("/repo/.env");
    expect(filesystem.denyRead).toEqual(["/"]);
    expect(filesystem.denyWrite).toEqual(["/repo/.env"]);
  });

  it("includes approved paths in SRT read and write allowances", () => {
    const filesystem = buildSrtRuntimeConfig(
      makeSpec({
        unmaskedPaths: [{ path: "/repo/.env", writable: true }],
        runtimeReadAllowPaths: ["/trusted/catalog", "/usr"],
      }),
    ).filesystem;

    expect(filesystem.allowRead).toEqual(["/trusted/catalog", "/usr", "/repo/.env"]);
    expect(filesystem.allowWrite).toEqual(["/repo", "/repo/app", "/shared-rw", "/repo/.env"]);
  });

  it("fails closed when env deny parity would be required", () => {
    expect(() =>
      buildSrtRuntimeConfig(
        makeSpec({ envDenyPatterns: ["*_TOKEN"] }),
      ),
    ).toThrowError("SRT helper path does not yet support env deny pattern parity.");
  });

  it("allows validated Docker sockets through filesystem and Unix-socket rules", () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("darwin");
    vi.spyOn(dockerSocket, "resolveDockerSocketPaths").mockReturnValue(["/var/run/docker.sock"]);

    const config = buildSrtRuntimeConfig(makeSpec({ command: "docker info", allowDocker: true }));

    expect(config.dockerHost).toBe("unix:///var/run/docker.sock");
    expect(config.filesystem.allowRead).toContain("/var/run/docker.sock");
    expect(config.network?.allowUnixSockets).toEqual(["/var/run/docker.sock"]);
  });

  it("allows all Unix sockets by default on Linux while preserving Docker approval", () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    vi.spyOn(dockerSocket, "resolveDockerSocketPaths").mockReturnValue(["/var/run/docker.sock"]);

    const config = buildSrtRuntimeConfig(makeSpec({ command: "docker info", allowDocker: true }));

    expect(config.network?.allowAllUnixSockets).toBe(true);
    expect(config.network?.allowUnixSockets).toEqual(["/var/run/docker.sock"]);
    expect(config.dockerHost).toBe("unix:///var/run/docker.sock");
  });

  it("does not emit the platform default on unsupported platforms", () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("win32");

    expect(buildSrtRuntimeConfig(makeSpec()).network).not.toHaveProperty("allowAllUnixSockets");
  });

  it("fails closed when Docker socket resolution returns no socket", () => {
    vi.spyOn(dockerSocket, "resolveDockerSocketPaths").mockReturnValue([]);

    expect(() =>
      buildSrtRuntimeConfig(makeSpec({ command: "docker info", allowDocker: true })),
    ).toThrowError("Docker socket unavailable; command blocked.");
  });
});
