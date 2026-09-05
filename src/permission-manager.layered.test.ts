import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { FilePolicyLoader } from "./policy-loader";
import { PermissionManager } from "./permission-manager";

const tempPaths: string[] = [];

afterEach(async () => {
  delete process.env.PI_SECURITY_SCAN_PROFILE;
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("PermissionManager bundled defaults", () => {
  it("enforces bundled permission rules before user overrides", () => {
    const loader = {
      loadBundledConfig: () => ({ permission: { write: "deny", edit: "deny" } }),
      loadGlobalConfig: () => ({ permission: { write: "allow" } }),
      loadProjectConfig: () => ({}),
      loadAgentConfig: () => ({}),
      loadProjectAgentConfig: () => ({}),
      loadSecurityProfileConfig: () => ({}),
      getConfiguredMcpServerNames: () => [],
      getCacheStamp: () => "test",
      getConfigIssues: () => [],
      getResolvedPolicyPaths: () => ({
        bundledConfigPath: "bundled/config.json",
        bundledConfigExists: true,
        globalConfigPath: "global/permissions.json",
        globalConfigExists: true,
        projectConfigPath: null,
        projectConfigExists: false,
        agentsDir: "agents",
        agentsDirExists: false,
        projectAgentsDir: null,
        projectAgentsDirExists: false,
      }),
    };

    const manager = new PermissionManager({ policyLoader: loader as never });

    expect(manager.getToolPermission("write")).toBe("allow");
    expect(manager.checkPermission("write", {})).toMatchObject({
      state: "allow",
      origin: "global",
    });
    expect(manager.checkPermission("edit", {})).toMatchObject({
      state: "deny",
      origin: "bundled",
    });
  });

  it("allows intercom extension calls under a universal ask fallback", async () => {
    const fixtureDir = await mkdtemp(path.join(tmpdir(), "pi-intercom-policy-"));
    tempPaths.push(fixtureDir);
    const bundledConfigPath = path.join(fixtureDir, "config.json");
    const globalConfigPath = path.join(fixtureDir, "permissions.json");
    await writeFile(bundledConfigPath, JSON.stringify({ permission: { "*": "ask" } }), "utf8");
    await writeFile(globalConfigPath, JSON.stringify({ permission: { intercom: "allow" } }), "utf8");

    const manager = new PermissionManager({
      policyLoader: new FilePolicyLoader({
        bundledConfigPath,
        globalConfigPath,
        agentsDir: path.join(fixtureDir, "missing-agents"),
        globalMcpConfigPath: path.join(fixtureDir, "missing-mcp.json"),
      }),
    });

    expect(manager.getToolPermission("intercom")).toBe("allow");
    expect(manager.checkPermission("intercom", { action: "send" })).toMatchObject({
      state: "allow",
      source: "tool",
      origin: "global",
    });
  });

  it("loads security profiles beside bundled defaults", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "pi-profile-layer-"));
    tempPaths.push(root);
    const bundledConfigPath = path.join(root, "extension", "config.json");
    const profilePath = path.join(root, "extension", "profiles", "security-scan.json");
    const globalConfigPath = path.join(root, "agent", "permissions.json");
    await mkdir(path.dirname(bundledConfigPath), { recursive: true });
    await mkdir(path.dirname(profilePath), { recursive: true });
    await mkdir(path.dirname(globalConfigPath), { recursive: true });
    await writeFile(bundledConfigPath, JSON.stringify({ permission: { write: "deny" } }), "utf8");
    await writeFile(profilePath, JSON.stringify({ "scan-remediation": { write: "allow" } }), "utf8");
    await writeFile(globalConfigPath, JSON.stringify({}), "utf8");
    process.env.PI_SECURITY_SCAN_PROFILE = "scan-remediation";

    const manager = new PermissionManager({
      policyLoader: new FilePolicyLoader({
        bundledConfigPath,
        globalConfigPath,
        agentsDir: path.join(root, "agents"),
      }),
    });

    expect(manager.getToolPermission("write")).toBe("allow");
  });
});
