import { describe, expect, it, vi } from "vitest";

import { canonicalPath } from "./sandbox-visible-paths.js";

const planState = vi.hoisted(() => ({
  calls: [] as Array<{ scanRoots?: string[] }>,
  unscannedRoots: [] as Array<{ root: string; reason: string }>,
}));

vi.mock("./masked-command-shim.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./masked-command-shim.js")>();
  return {
    ...actual,
    buildMaskedCommandShimPlan: (_command: string, _profile: unknown, _cwd: string, options: { scanRoots?: string[] } = {}) => {
      planState.calls.push(options);
      return { maskedFilePaths: [], maskedDenyPaths: [], shimCommands: [], unscannedRoots: planState.unscannedRoots };
    },
  };
});

import { buildSrtCommandSpec, MaskedScanUnavailableError } from "./srt-command-spec.js";

const repo = canonicalPath(process.cwd());

function specInput(extra: Record<string, unknown> = {}) {
  return {
    command: "ls -la ~/.local",
    cwd: repo,
    repoRoot: repo,
    sandboxConfig: { enabled: true, backend: "srt", profiles: {}, defaultProfile: "online-dev", roBinds: [], rwBinds: [] } as never,
    profile: { name: "online-dev", network: true, allowDocker: false, roBinds: [], rwBinds: [], env: { allow: [], deny: [] }, maskedPaths: [] } as never,
    ...extra,
  } as never;
}

describe("buildSrtCommandSpec scan approval", () => {
  it("throws MaskedScanUnavailableError with the unscannable roots", () => {
    planState.calls.length = 0;
    planState.unscannedRoots = [{ root: "/unscannable/example", reason: "timed out" }];

    expect(() => buildSrtCommandSpec(specInput())).toThrow(MaskedScanUnavailableError);
  });

  it("does not scan a root the user already approved", () => {
    planState.calls.length = 0;
    planState.unscannedRoots = [];

    buildSrtCommandSpec(specInput({ scanApprovedRoots: [repo] }));

    expect(planState.calls.at(-1)?.scanRoots ?? []).not.toContain(repo);
  });
});
