import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildSrtNetworkPlan,
  buildSrtNetworkPlanFromConfig,
} from "./srt-network-plan.js";

const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  delete process.env.PI_CODING_AGENT_DIR;
  vi.restoreAllMocks();
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("buildSrtNetworkPlan", () => {
  it("uses permissive unmatched-host callback semantics when domain gate is disabled", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: false,
          unknownDomains: "ask",
          allowedDomains: ["github.com"],
          deniedDomains: ["blocked.example.com"],
        },
        approvedDomains: ["api.github.com"],
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "allow",
      config: {
        allowedDomains: [],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: false,
      },
    });
  });

  it("blocks all network when sandbox network is off", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: false,
        domainPolicy: { enabled: true, unknownDomains: "allow", allowedDomains: ["github.com"], deniedDomains: [] },
        approvedDomains: ["api.github.com"],
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: [],
        deniedDomains: [],
        strictAllowlist: true,
      },
    });
  });

  it("uses strict allowlist semantics for unknownDomains=ask even before approvals", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: true,
          unknownDomains: "ask",
          allowedDomains: ["github.com"],
          deniedDomains: ["blocked.example.com"],
        },
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: true,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: ["github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
      },
    });
  });

  it("uses strict allowlist for unknownDomains=ask when specific domains were approved", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: true,
          unknownDomains: "ask",
          allowedDomains: ["github.com", "api.github.com"],
          deniedDomains: ["blocked.example.com"],
        },
        approvedDomains: ["npmjs.org", "api.github.com", "npmjs.org"],
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: true,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: ["github.com", "api.github.com", "npmjs.org"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
      },
    });
  });

  it("maps unknownDomains=allow to permissive unmatched-host behavior", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: true,
          unknownDomains: "allow",
          allowedDomains: ["github.com"],
          deniedDomains: ["blocked.example.com"],
        },
        approvedDomains: ["api.github.com"],
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "allow",
      config: {
        allowedDomains: ["github.com", "api.github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: false,
      },
    });
  });

  it("maps unknownDomains=deny to strict allowlist without outer prompt", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: true,
          unknownDomains: "deny",
          allowedDomains: ["github.com"],
          deniedDomains: ["blocked.example.com"],
        },
        approvedDomains: ["api.github.com"],
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: ["github.com", "api.github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
      },
    });
  });

  it("expands current wildcard semantics so apex domains stay aligned with outer gate", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: true,
          unknownDomains: "deny",
          allowedDomains: ["*.github.com"],
          deniedDomains: ["*.blocked.example.com"],
        },
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: ["github.com", "*.github.com"],
        deniedDomains: ["blocked.example.com", "*.blocked.example.com"],
        strictAllowlist: true,
      },
    });
  });

  it("treats allow-all wildcard as callback-driven permissive mode, not literal allowedDomains entry", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: true,
          unknownDomains: "deny",
          allowedDomains: ["*"],
          deniedDomains: ["blocked.example.com"],
        },
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "allow",
      config: {
        allowedDomains: [],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: false,
      },
    });
  });

  it("treats deny-all wildcard as strict deny-all mode without forwarding invalid SRT wildcard entries", () => {
    expect(
      buildSrtNetworkPlan({
        sandboxNetworkEnabled: true,
        domainPolicy: {
          enabled: true,
          unknownDomains: "allow",
          allowedDomains: ["github.com"],
          deniedDomains: ["*"],
        },
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: [],
        deniedDomains: [],
        strictAllowlist: true,
      },
    });
  });
});

describe("buildSrtNetworkPlanFromConfig", () => {
  it("resolves the same project legacy domain policy path as the current outer gate", async () => {
    const agentDir = await makeTempDir("pi-srt-network-agent-");
    const projectDir = await makeTempDir("pi-srt-network-project-");
    const projectConfigDir = path.join(projectDir, ".pi");

    process.env.PI_CODING_AGENT_DIR = agentDir;
    await mkdir(projectConfigDir, { recursive: true });
    await writeFile(
      path.join(projectConfigDir, "domain-gate.json"),
      JSON.stringify({
        enabled: true,
        unknownDomains: "deny",
        allowedDomains: ["github.com"],
        deniedDomains: ["blocked.example.com"],
      }),
      "utf8",
    );

    expect(
      buildSrtNetworkPlanFromConfig({
        sandboxNetworkEnabled: true,
        config: undefined,
        cwd: projectDir,
        approvedDomains: ["api.github.com"],
      }),
    ).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: ["github.com", "api.github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
      },
    });
  });
});
