import { describe, expect, it } from "vitest";

import { buildSrtRuntimeConfig } from "./srt-runtime-config.js";
import type { SrtCommandSpec } from "./srt-command-spec.js";

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
  it("translates command spec into filesystem and network config", () => {
    expect(buildSrtRuntimeConfig(makeSpec())).toEqual({
      network: {
        allowedDomains: ["github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
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

  it("fails closed when Docker passthrough would be required", () => {
    expect(() =>
      buildSrtRuntimeConfig(
        makeSpec({ allowDocker: true }),
      ),
    ).toThrowError("SRT helper path does not yet support Docker socket passthrough.");
  });
});
