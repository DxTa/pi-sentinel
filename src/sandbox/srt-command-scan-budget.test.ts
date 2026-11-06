import { describe, expect, it, vi } from "vitest";

import { canonicalPath } from "./sandbox-visible-paths.js";

vi.mock("./masked-command-shim.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./masked-command-shim.js")>();
  return {
    ...actual,
    // A scan that takes longer than the whole preparation budget, and finds nothing unscannable.
    buildMaskedCommandShimPlanAsync: async () => {
      await new Promise((resolve) => setTimeout(resolve, 400));
      return { maskedFilePaths: [], maskedDenyPaths: [], shimCommands: [], unscannedRoots: [] };
    },
  };
});

import { buildSrtCommandSpecAsync } from "./srt-command-spec.js";

const repo = canonicalPath(process.cwd());

describe("buildSrtCommandSpecAsync scan budget", () => {
  it("does not fail after the masked scan consumes the budget", async () => {
    const input = {
      command: "ls",
      cwd: repo,
      repoRoot: repo,
      sandboxConfig: { enabled: true, backend: "srt", profiles: {}, defaultProfile: "online-dev", roBinds: [], rwBinds: [] } as never,
      profile: { name: "online-dev", network: true, allowDocker: false, roBinds: [], rwBinds: [], env: { allow: [], deny: [] }, maskedPaths: [] } as never,
      unmaskedPaths: [{ path: repo + "/package.json", writable: false }],
    };

    await expect(buildSrtCommandSpecAsync(input, 300)).resolves.toMatchObject({ cwd: repo });
  });
});
