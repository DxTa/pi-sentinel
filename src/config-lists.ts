import type { Rule } from "./rule";
import type { SessionRules } from "./session-rules";
import type { PermissionState } from "./types";
import {
  getSessionHostFallbacks,
  getSessionYoloAskPatterns,
  setSessionHostFallback,
  setSessionYoloAskPattern,
} from "./session-lists";
import {
  getSessionDomainGrants,
  approveSessionDomains,
  denySessionDomains,
  removeSessionDomain,
} from "./network/session-domains";
import {
  getScopedConfigPath,
  listHostFallbackCommands,
  listNetworkDomains,
  listPermissionRules,
  listSandboxPaths,
  listYoloAskPatterns,
  persistPermissionRuleToConfig,
  persistSandboxPathGrantToConfig,
  removePermissionRule,
  removeSandboxPathGrantFromConfig,
  setHostFallbackCommand,
  setNetworkDomainState,
  setYoloAskPattern,
} from "./scoped-config";

export type ConfigListKind = "networkDomain" | "sandboxPath" | "hostFallback" | "yoloAskPattern" | "permissionRule";
export type ConfigListScope = "session" | "project" | "global";

/** `state` is the entry's decision (allow, deny, ask, ro, rw) or "on" for plain string lists. */
export interface ConfigListEntry {
  value: string;
  state: string;
  /** Permission surface (tool name); set for permission rules only. */
  surface?: string;
}

/** Session-scoped permission rules; satisfied by `SessionRules` and by the session owner. */
export type SessionRuleStore = Pick<SessionRules, "approve" | "deny" | "remove"> & { getRuleset(): Rule[] };

export interface ConfigListContext {
  agentDir: string;
  cwd: string | null;
  sessionRules?: SessionRuleStore;
  sandboxGrants?: SessionSandboxGrantStore;
}

/** Session-scoped sandbox path grants; satisfied by the sandbox policy manager adapter. */
export interface SessionSandboxGrantStore {
  listPathGrants(): Array<{ value: string; mode: "ro" | "rw" }>;
  grantPath(value: string, mode: "ro" | "rw"): void;
  revokePath(value: string): void;
}

/** Session scope needs its store for rules and sandbox paths; domains, host fallbacks, and yolo patterns are built in. */
function assertSessionSupported(kind: ConfigListKind, scope: ConfigListScope, ctx: ConfigListContext): void {
  if (scope !== "session") return;
  if (kind === "permissionRule" && ctx.sessionRules) return;
  if (kind === "sandboxPath" && ctx.sandboxGrants) return;
  if (kind === "networkDomain" || kind === "hostFallback" || kind === "yoloAskPattern") return;
  throw new Error(`${kind} has no session scope yet.`);
}

function requireSurface(surface: string | undefined): string {
  if (!surface) throw new Error("A permission rule needs a surface.");
  return surface;
}

function fileTarget(ctx: ConfigListContext, scope: Exclude<ConfigListScope, "session">): {
  configPath: string;
  workspaceRoot?: string;
} {
  if (scope === "project") {
    if (!ctx.cwd) throw new Error("Project scope needs a working directory.");
    return { configPath: getScopedConfigPath(ctx.agentDir, ctx.cwd, "workspace"), workspaceRoot: ctx.cwd };
  }
  return { configPath: getScopedConfigPath(ctx.agentDir, ctx.cwd, "global") };
}

export function listConfigList(
  ctx: ConfigListContext,
  kind: ConfigListKind,
  scope: ConfigListScope,
): ConfigListEntry[] {
  assertSessionSupported(kind, scope, ctx);
  if (scope === "session") {
    if (kind === "permissionRule") {
      return ctx.sessionRules!.getRuleset()
        .filter((rule) => rule.origin === "session")
        .map((rule) => ({ surface: rule.surface, value: rule.pattern, state: rule.action }));
    }
    if (kind === "sandboxPath") {
      return ctx.sandboxGrants!.listPathGrants().map((grant) => ({ value: grant.value, state: grant.mode }));
    }
    if (kind === "hostFallback") {
      return getSessionHostFallbacks().map((value) => ({ value, state: "on" }));
    }
    if (kind === "yoloAskPattern") {
      return getSessionYoloAskPatterns().map((value) => ({ value, state: "on" }));
    }
    const grants = getSessionDomainGrants();
    return [
      ...grants.allowed.map((value) => ({ value, state: "allow" })),
      ...grants.denied.map((value) => ({ value, state: "deny" })),
    ];
  }
  const { configPath, workspaceRoot } = fileTarget(ctx, scope);
  switch (kind) {
    case "networkDomain": {
      const lists = listNetworkDomains(configPath, workspaceRoot);
      return [
        ...lists.allowed.map((value) => ({ value, state: "allow" })),
        ...lists.denied.map((value) => ({ value, state: "deny" })),
      ];
    }
    case "permissionRule":
      return listPermissionRules(configPath, workspaceRoot).map((rule) => ({
        surface: rule.surface,
        value: rule.pattern,
        state: rule.action,
      }));
    case "sandboxPath": {
      const paths = listSandboxPaths(configPath, workspaceRoot);
      return [
        ...paths.ro.map((value) => ({ value, state: "ro" })),
        ...paths.rw.map((value) => ({ value, state: "rw" })),
      ];
    }
    case "hostFallback":
      return listHostFallbackCommands(configPath, workspaceRoot).map((value) => ({ value, state: "on" }));
    case "yoloAskPattern":
      return listYoloAskPatterns(configPath, workspaceRoot).map((value) => ({ value, state: "on" }));
  }
}

/**
 * Set one entry's state. `state` is allow/deny/ask/ro/rw for its kind, "on" for
 * plain string lists, or "remove" to drop the entry. Permission rules need `surface`.
 */
export function editConfigList(
  ctx: ConfigListContext,
  kind: ConfigListKind,
  scope: ConfigListScope,
  value: string,
  state: string,
  surface?: string,
): void {
  assertSessionSupported(kind, scope, ctx);
  const remove = state === "remove";
  if (scope === "session") {
    if (kind === "permissionRule") {
      const rule = requireSurface(surface);
      if (remove) ctx.sessionRules!.remove(rule, value);
      else if (state === "allow") ctx.sessionRules!.approve(rule, value);
      else ctx.sessionRules!.deny(rule, value);
      return;
    }
    if (kind === "sandboxPath") {
      if (remove) ctx.sandboxGrants!.revokePath(value);
      else ctx.sandboxGrants!.grantPath(value, state as "ro" | "rw");
      return;
    }
    if (kind === "hostFallback") {
      setSessionHostFallback(value, !remove);
      return;
    }
    if (kind === "yoloAskPattern") {
      setSessionYoloAskPattern(value, !remove);
      return;
    }
    if (state === "allow") approveSessionDomains([value]);
    else if (state === "deny") denySessionDomains([value]);
    else removeSessionDomain(value);
    return;
  }
  const { configPath, workspaceRoot } = fileTarget(ctx, scope);
  switch (kind) {
    case "networkDomain":
      setNetworkDomainState(configPath, value, remove ? "remove" : (state as "allow" | "deny"), workspaceRoot);
      return;
    case "permissionRule": {
      const rule = requireSurface(surface);
      if (remove) removePermissionRule(configPath, rule, value, workspaceRoot);
      else persistPermissionRuleToConfig(configPath, rule, value, state as PermissionState, workspaceRoot);
      return;
    }
    case "sandboxPath":
      if (remove) removeSandboxPathGrantFromConfig(configPath, value, workspaceRoot);
      else persistSandboxPathGrantToConfig(configPath, value, state as "ro" | "rw", workspaceRoot);
      return;
    case "hostFallback":
      setHostFallbackCommand(configPath, value, !remove, workspaceRoot);
      return;
    case "yoloAskPattern":
      setYoloAskPattern(configPath, value, !remove, workspaceRoot);
      return;
  }
}
