import { describe, expect, it } from "vitest";

import { createPiMcpToolTargets } from "./mcp-targets";
import { PermissionManager } from "./permission-manager";

type Permission = Record<string, unknown>;
const empty = () => ({});
function manager(bundled: Permission, global: Permission = {}) {
  const loader = {
    loadBundledConfig: () => ({ permission: bundled }),
    loadGlobalConfig: () => ({ permission: global }),
    loadProjectConfig: empty, loadAgentConfig: empty, loadProjectAgentConfig: empty,
    loadSecurityProfileConfig: empty, getConfiguredMcpServerNames: () => [],
    getCacheStamp: () => JSON.stringify([bundled, global]), getConfigIssues: () => [],
    getResolvedPolicyPaths: () => ({
      bundledConfigPath: "b", bundledConfigExists: true, globalConfigPath: "g", globalConfigExists: true,
      projectConfigPath: null, projectConfigExists: false, agentsDir: "a", agentsDirExists: false,
      projectAgentsDir: null, projectAgentsDirExists: false,
    }),
  };
  return new PermissionManager({ policyLoader: loader as never });
}
const BUNDLED = { "*": "ask", mcp: { "*": "ask", mcp_status: "allow" } };

describe("createPiMcpToolTargets", () => {
  it("derives server-qualified targets, most specific first", () => {
    expect(createPiMcpToolTargets("mcp__github__get_issue")).toEqual(["github_get_issue", "github:get_issue", "github"]);
    expect(createPiMcpToolTargets("mcp__my_srv__list__all")).toEqual(["my_srv_list__all", "my_srv:list__all", "my_srv"]);
  });

  it("ignores names that are not pi MCP tools", () => {
    expect(createPiMcpToolTargets("mcp")).toBeNull();
    expect(createPiMcpToolTargets("codemode")).toBeNull();
    expect(createPiMcpToolTargets("mcp__onlyserver")).toBeNull();
  });
});

describe("pi MCP tools use permission.mcp rules", () => {
  it("applies server and tool patterns from user config", () => {
    const pm = manager(BUNDLED, { mcp: { "github_*": "allow", "github_delete_*": "deny" } });
    expect(pm.checkPermission("mcp__github__get_issue", {})).toMatchObject({ state: "allow", source: "mcp", target: "github_get_issue" });
    expect(pm.checkPermission("mcp__github__delete_repository", {})).toMatchObject({ state: "deny", source: "mcp" });
    expect(pm.getToolPermission("mcp__github__delete_repository")).toBe("deny");
  });

  it("lets a rule on the full tool name win over permission.mcp", () => {
    const pm = manager(BUNDLED, { mcp: { "github_*": "allow" }, mcp__github__get_issue: "deny" });
    expect(pm.checkPermission("mcp__github__get_issue", {})).toMatchObject({ state: "deny", source: "tool" });
  });

  it("keeps the universal fallback when only bundled mcp rules match", () => {
    expect(manager(BUNDLED, { "*": "deny" }).checkPermission("mcp__github__get_issue", {}).state).toBe("deny");
    expect(manager({ ...BUNDLED, mcp: { "*": "allow" } }).checkPermission("mcp__github__get_issue", {}).state).toBe("ask");
  });

  it("does not let proxy metadata baselines allow a server tool", () => {
    const pm = manager(BUNDLED, { mcp: { "other_*": "allow" } });
    expect(pm.checkPermission("mcp__mcp__status", {}).state).toBe("ask");
    expect(pm.checkPermission("mcp__github__get_issue", {}).state).toBe("ask");
  });
});
