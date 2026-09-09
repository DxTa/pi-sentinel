import { describe, expect, it } from "vitest";

import { createSrtBackend } from "./srt-backend.js";
import type { SandboxConfig, ResolvedSandboxProfile } from "../types.js";

function makeConfig(): SandboxConfig {
  return {
    enabled: true,
    backend: "srt",
    profiles: {},
    defaultProfile: "online-dev",
    roBinds: [],
    rwBinds: [],
  };
}

function makeProfile(overrides: Partial<ResolvedSandboxProfile> = {}): ResolvedSandboxProfile {
  return {
    name: "online-dev",
    network: true,
    allowDocker: false,
    roBinds: [],
    rwBinds: [],
    env: { allow: [], deny: [] },
    maskedPaths: [],
    ...overrides,
  };
}

describe("createSrtBackend masked-path parity", () => {
  it("allows SRT shim path for direct cat masked file reads", { timeout: 30_000 }, async () => {
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

    const result = await backend.wrapCommand({
      command: "cat .env",
      sandboxConfig: makeConfig(),
      cwd: "/repo",
      preResolvedProfile: makeProfile({ maskedPaths: ["**/.env"] }),
      unifiedConfig: { network: { enabled: true, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] } },
    });

    expect(result && "command" in result).toBe(true);
  });
});
