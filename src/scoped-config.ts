import {
  closeSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

import { isPathWithinDirectory } from "./path-utils";

import { loadAndMergeConfigs, stripJsonComments } from "./config-loader";
import {
  getBundledConfigPath,
  getGlobalConfigPath,
  getLegacyGlobalPolicyPath,
  getLegacyProjectConfigPath,
  getLegacyProjectExtensionConfigPath,
  getLegacyProjectPolicyPath,
  getProjectConfigPath,
} from "./config-paths";
import { EXTENSION_ROOT } from "./extension-config";
import { mergeFlatPermissions } from "./permission-merge";
import type { FlatPermissionConfig, PermissionState } from "./types";

export type PersistentApprovalScope = "global" | "workspace";

type JsonObject = Record<string, unknown>;

function requireConfigObject(value: unknown, section: string): JsonObject {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${section} configuration; expected object.`);
  }
  return value as JsonObject;
}

function dedupeStrings(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

function toStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? dedupeStrings(value.filter((entry): entry is string => typeof entry === "string"))
    : [];
}

export function readConfigFile(path: string): JsonObject {
  if (!existsSync(path)) {
    return {};
  }

  const raw = readFileSync(path, "utf-8");
  try {
    return requireConfigObject(JSON.parse(stripJsonComments(raw)) as unknown, "config");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse config at '${path}': ${message}`);
  }
}

function readConfigLayer(path: string): JsonObject {
  return readConfigFile(path);
}

function canonicalizeConfigPath(configPath: string): string {
  const resolvedPath = resolve(configPath);
  try {
    return realpathSync.native(resolvedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const missingParents: string[] = [];
  let parent = dirname(resolvedPath);
  while (!existsSync(parent)) {
    const next = dirname(parent);
    if (next === parent) throw new Error(`Config parent does not exist: '${configPath}'.`);
    missingParents.unshift(basename(parent));
    parent = next;
  }
  return resolve(realpathSync.native(parent), ...missingParents, basename(resolvedPath));
}

export function writeConfigFile(
  path: string,
  config: JsonObject,
  workspaceRoot?: string,
): boolean {
  let targetPath = path;
  let tempPath: string | undefined;
  try {
    targetPath = workspaceRoot
      ? resolveConfinedConfigPath(path, workspaceRoot)
      : canonicalizeConfigPath(path);
    if (existsSync(targetPath)) {
      const stat = lstatSync(targetPath);
      if (!stat.isFile()) return false;
    }

    mkdirSync(dirname(targetPath), { recursive: true, mode: 0o700 });
    tempPath = `${targetPath}.${randomUUID()}.tmp`;
    if (workspaceRoot && resolveConfinedConfigPath(path, workspaceRoot) !== targetPath) {
      return false;
    }
    const tempFd = openSync(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    try {
      const hasLegacyMode =
        typeof config.yoloMode === "boolean" || typeof config.yoloAutoMode === "boolean";
      const canonicalConfig = canonicalizePersistedMode(
        config,
        hasLegacyMode ? resolveEffectiveModeForWrite(path, workspaceRoot) : undefined,
      );
      writeFileSync(tempFd, `${JSON.stringify(canonicalConfig, null, 2)}\n`, "utf-8");
    } finally {
      closeSync(tempFd);
    }
    if (workspaceRoot && resolveConfinedConfigPath(path, workspaceRoot) !== targetPath) {
      unlinkSync(tempPath);
      return false;
    }
    renameSync(tempPath, targetPath);
    return true;
  } catch {
    try {
      if (tempPath && existsSync(tempPath)) unlinkSync(tempPath);
    } catch {
      // Ignore cleanup failures.
    }
    return false;
  }
}

function legacyFlagsForMode(mode: unknown): { yoloMode?: boolean; yoloAutoMode?: boolean } {
  if (mode === "auto") return { yoloMode: true, yoloAutoMode: true };
  if (mode === "yolo") return { yoloMode: true, yoloAutoMode: false };
  if (mode === "manual") return { yoloMode: false, yoloAutoMode: false };
  return {};
}

function resolveEffectiveModeForWrite(
  configPath: string,
  workspaceRoot?: string,
): unknown {
  const agentDir = workspaceRoot
    ? process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent")
    : dirname(configPath);
  try {
    return loadAndMergeConfigs(
      agentDir,
      workspaceRoot ?? null,
      EXTENSION_ROOT,
    ).configuredMode;
  } catch {
    return undefined;
  }
}

function canonicalizePersistedMode(
  config: JsonObject,
  inheritedMode: unknown,
): JsonObject {
  const next = { ...config };
  const mode = next.mode;
  const hasLegacyMode =
    typeof next.yoloMode === "boolean" || typeof next.yoloAutoMode === "boolean";
  if (mode !== "manual" && mode !== "yolo" && mode !== "auto" && hasLegacyMode) {
    const inherited = legacyFlagsForMode(inheritedMode);
    const effective = {
      ...inherited,
      ...(typeof next.yoloMode === "boolean" ? { yoloMode: next.yoloMode } : {}),
      ...(typeof next.yoloAutoMode === "boolean" ? { yoloAutoMode: next.yoloAutoMode } : {}),
    };
    if (effective.yoloAutoMode === true) next.mode = "auto";
    else if (effective.yoloMode === true) next.mode = "yolo";
    else if (effective.yoloAutoMode !== undefined || effective.yoloMode !== undefined) {
      next.mode = "manual";
    }
  }
  delete next.yoloMode;
  delete next.yoloAutoMode;
  return next;
}

function readConfigForWrite(path: string): JsonObject | null {
  try {
    return readConfigFile(path);
  } catch {
    return null;
  }
}

function mergeObject(base: JsonObject, override: JsonObject): JsonObject {
  const merged: JsonObject = { ...base };

  for (const [key, value] of Object.entries(override)) {
    const baseValue = merged[key];
    if (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      baseValue &&
      typeof baseValue === "object" &&
      !Array.isArray(baseValue)
    ) {
      merged[key] = mergeObject(
        baseValue as JsonObject,
        value as JsonObject,
      );
      continue;
    }
    merged[key] = value;
  }

  return merged;
}

function mergeNetworkConfig(baseValue: unknown, overrideValue: unknown): JsonObject | undefined {
  const base = requireConfigObject(baseValue, "network");
  const override = requireConfigObject(overrideValue, "network");
  if (Object.keys(base).length === 0 && Object.keys(override).length === 0) {
    return undefined;
  }

  const overrideAllowed = toStringArray(override.allowedDomains);
  const overrideDenied = toStringArray(override.deniedDomains);
  const allowedDomains = dedupeStrings([
    ...toStringArray(base.allowedDomains).filter((entry) => !overrideDenied.includes(entry)),
    ...overrideAllowed.filter((entry) => !overrideDenied.includes(entry)),
  ]);
  const deniedDomains = dedupeStrings([
    ...toStringArray(base.deniedDomains),
    ...overrideDenied,
  ]);

  const merged: JsonObject = {};
  if (base.enabled !== undefined || override.enabled !== undefined) {
    merged.enabled = override.enabled ?? base.enabled;
  }
  if (base.unknownDomains !== undefined || override.unknownDomains !== undefined) {
    merged.unknownDomains = override.unknownDomains ?? base.unknownDomains;
  }
  if (
    allowedDomains.length > 0 ||
    base.allowedDomains !== undefined ||
    override.allowedDomains !== undefined
  ) {
    merged.allowedDomains = allowedDomains;
  }
  if (
    deniedDomains.length > 0 ||
    base.deniedDomains !== undefined ||
    override.deniedDomains !== undefined
  ) {
    merged.deniedDomains = deniedDomains;
  }
  return merged;
}

function mergeSandboxConfig(baseValue: unknown, overrideValue: unknown): JsonObject | undefined {
  const base = requireConfigObject(baseValue, "sandbox");
  const override = requireConfigObject(overrideValue, "sandbox");
  if (Object.keys(base).length === 0 && Object.keys(override).length === 0) {
    return undefined;
  }

  const merged = mergeObject(base, override);
  const roBinds = dedupeStrings([
    ...toStringArray(base.roBinds),
    ...toStringArray(override.roBinds),
  ]);
  const rwBinds = dedupeStrings([
    ...toStringArray(base.rwBinds),
    ...toStringArray(override.rwBinds),
  ]);
  if (roBinds.length > 0) {
    merged.roBinds = roBinds;
  }
  if (rwBinds.length > 0) {
    merged.rwBinds = rwBinds;
  }
  return merged;
}

function mergePermissionConfig(baseValue: unknown, overrideValue: unknown): FlatPermissionConfig | undefined {
  const base = requireConfigObject(baseValue, "permission") as FlatPermissionConfig;
  const override = requireConfigObject(overrideValue, "permission") as FlatPermissionConfig;
  const hasBase = Object.keys(base).length > 0;
  const hasOverride = Object.keys(override).length > 0;
  if (!hasBase && !hasOverride) {
    return undefined;
  }
  if (!hasBase) return override;
  if (!hasOverride) return base;
  return mergeFlatPermissions(base, override);
}

export function resolveConfinedConfigPath(configPath: string, workspaceRoot: string): string {
  const resolvedPath = resolve(configPath);
  const logicalRoot = resolve(workspaceRoot);
  const canonicalRoot = realpathSync.native(logicalRoot);
  let followsSymlink = false;

  try {
    const configStat = lstatSync(resolvedPath);
    if (configStat.isSymbolicLink()) {
      followsSymlink = true;
      if (!lstatSync(realpathSync.native(resolvedPath)).isFile()) {
        throw new Error(`Workspace config target is not a regular file: '${configPath}'.`);
      }
    } else if (!configStat.isFile()) {
      throw new Error(`Workspace config target is not a regular file: '${configPath}'.`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const missingParents: string[] = [];
  let parent = dirname(resolvedPath);
  while (!existsSync(parent)) {
    const next = dirname(parent);
    if (next === parent) {
      throw new Error(`Workspace config parent does not exist: '${configPath}'.`);
    }
    missingParents.unshift(basename(parent));
    parent = next;
  }

  let current = parent;
  while (true) {
    const parentStat = lstatSync(current);
    if (!parentStat.isDirectory() && !parentStat.isSymbolicLink()) {
      throw new Error(`Workspace config parent is not a directory: '${configPath}'.`);
    }
    followsSymlink ||= parentStat.isSymbolicLink();
    const next = dirname(current);
    if (next === current) break;
    current = next;
  }

  const relativeParent = relative(logicalRoot, parent);
  if (relativeParent.startsWith(`..${sep}`) || relativeParent === ".." || resolve(logicalRoot, relativeParent) !== parent) {
    throw new Error(`Workspace config path escapes workspace: '${configPath}'.`);
  }
  const canonicalPath = canonicalizeConfigPath(resolvedPath);
  if (!isPathWithinDirectory(canonicalPath, canonicalRoot) && !followsSymlink) {
    throw new Error(`Workspace config path escapes workspace: '${configPath}'.`);
  }
  return canonicalPath;
}

export function getScopedConfigPath(
  agentDir: string,
  cwd: string | undefined | null,
  scope: PersistentApprovalScope,
): string {
  if (scope === "workspace") {
    if (!cwd) {
      return getGlobalConfigPath(agentDir);
    }
    const projectPath = getProjectConfigPath(cwd);
    if (existsSync(projectPath)) return projectPath;
    const legacyProjectPath = getLegacyProjectConfigPath(cwd);
    return existsSync(legacyProjectPath) ? legacyProjectPath : projectPath;
  }
  return getGlobalConfigPath(agentDir);
}

export function loadMergedScopedConfig(
  agentDir: string,
  cwd: string | undefined | null,
  bundledConfigPath = getBundledConfigPath(EXTENSION_ROOT),
): {
  bundledPath: string;
  globalPath: string;
  workspacePath: string | null;
  global: JsonObject;
  workspace: JsonObject;
  merged: JsonObject;
  scopedLayers: ScopedConfigLayer[];
} {
  const globalPath = getGlobalConfigPath(agentDir);
  const workspacePath = cwd
    ? resolveConfinedConfigPath(getProjectConfigPath(cwd), cwd)
    : null;
  const legacyWorkspacePath = cwd
    ? resolveConfinedConfigPath(getLegacyProjectConfigPath(cwd), cwd)
    : null;
  const legacyProjectPolicyPath = cwd
    ? resolveConfinedConfigPath(getLegacyProjectPolicyPath(cwd), cwd)
    : null;
  const legacyProjectExtensionConfigPath = cwd
    ? resolveConfinedConfigPath(getLegacyProjectExtensionConfigPath(cwd), cwd)
    : null;
  const global = readConfigLayer(globalPath);
  const workspace = mergeObject(
    legacyWorkspacePath ? readConfigLayer(legacyWorkspacePath) : {},
    workspacePath ? readConfigLayer(workspacePath) : {},
  );
  const scopedLayers: ScopedConfigLayer[] = [
    { scope: "default", config: readConfigLayer(bundledConfigPath) },
    { scope: "global", config: readConfigLayer(getLegacyGlobalPolicyPath(agentDir)) },
    { scope: "global", config: global },
    ...(cwd
      ? [
          legacyProjectPolicyPath ? readConfigLayer(legacyProjectPolicyPath) : {},
          legacyProjectExtensionConfigPath ? readConfigLayer(legacyProjectExtensionConfigPath) : {},
          legacyWorkspacePath ? readConfigLayer(legacyWorkspacePath) : {},
        ].map((config): ScopedConfigLayer => ({ scope: "project", config }))
      : []),
    { scope: "project", config: workspacePath ? readConfigLayer(workspacePath) : {} },
  ];

  let merged: JsonObject = {};
  for (const { config: layer } of scopedLayers) {
    const base = merged;
    merged = mergeObject(base, layer);
    const permission = mergePermissionConfig(base.permission, layer.permission);
    const network = mergeNetworkConfig(base.network, layer.network);
    const sandbox = mergeSandboxConfig(base.sandbox, layer.sandbox);
    if (permission !== undefined) merged.permission = permission;
    if (network !== undefined) merged.network = network;
    if (sandbox !== undefined) merged.sandbox = sandbox;
  }

  return { bundledPath: bundledConfigPath, globalPath, workspacePath, global, workspace, merged, scopedLayers };
}

/** Config file scope that last set a setting. `default` is the bundled config.json. */
export type SettingSource = "default" | "global" | "project";

export interface ScopedConfigLayer {
  scope: SettingSource;
  config: JsonObject;
}

/** Settings shown in `/sentinel` other than the mode, which has its own layer chain. */
export interface SettingSources {
  sandbox: SettingSource;
  permissionReviewLog: SettingSource;
  debugLog: SettingSource;
}

function lastScopeSetting(
  layers: readonly ScopedConfigLayer[],
  read: (config: JsonObject) => unknown,
): SettingSource {
  let source: SettingSource = "default";
  for (const layer of layers) {
    if (typeof read(layer.config) === "boolean") source = layer.scope;
  }
  return source;
}

/** Report which scope supplies each `/sentinel` toggle, using the same layers as the merge. */
export function getSettingSources(
  agentDir: string,
  cwd: string | undefined | null,
  bundledConfigPath = getBundledConfigPath(EXTENSION_ROOT),
): SettingSources {
  const { scopedLayers } = loadMergedScopedConfig(agentDir, cwd, bundledConfigPath);
  return {
    sandbox: lastScopeSetting(scopedLayers, (config) =>
      typeof config.sandbox === "object" && config.sandbox !== null && !Array.isArray(config.sandbox)
        ? (config.sandbox as JsonObject).enabled
        : undefined),
    permissionReviewLog: lastScopeSetting(scopedLayers, (config) => config.permissionReviewLog),
    debugLog: lastScopeSetting(scopedLayers, (config) => config.debugLog),
  };
}

export function persistPermissionRuleToConfig(
  configPath: string,
  surface: string,
  pattern: string,
  action: PermissionState = "allow",
  workspaceRoot?: string,
): JsonObject {
  const targetPath = workspaceRoot
    ? resolveConfinedConfigPath(configPath, workspaceRoot)
    : configPath;
  const current = readConfigForWrite(targetPath);
  if (!current) throw new Error(`Failed to read permission config at '${configPath}'.`);
  const permission = requireConfigObject(current.permission, "permission") as FlatPermissionConfig;
  const existing = permission[surface];

  if (pattern === "*" && typeof existing !== "object") {
    permission[surface] = action;
  } else {
    const next: Record<string, PermissionState> =
      typeof existing === "string"
        ? { "*": existing }
        : existing && typeof existing === "object"
          ? Object.fromEntries(
              Object.entries(existing as Record<string, PermissionState>).filter(
                ([existingPattern]) => existingPattern !== pattern,
              ),
            )
          : {};
    next[pattern] = action;
    permission[surface] = next;
  }

  const nextConfig = { ...current, permission };
  if (!writeConfigFile(configPath, nextConfig, workspaceRoot)) {
    throw new Error(`Failed to persist permission rule at '${configPath}'.`);
  }
  return nextConfig;
}

export function persistNetworkGrantToConfig(
  configPath: string,
  domain: string,
  state: "allow" | "deny" = "allow",
  workspaceRoot?: string,
): JsonObject {
  const targetPath = workspaceRoot
    ? resolveConfinedConfigPath(configPath, workspaceRoot)
    : configPath;
  const current = readConfigForWrite(targetPath);
  if (!current) throw new Error(`Failed to read network config at '${configPath}'.`);
  const network = requireConfigObject(current.network, "network");
  const value = domain.trim();
  if (!value) return current;

  const allowedDomains = state === "allow"
    ? dedupeStrings([...toStringArray(network.allowedDomains), value])
    : toStringArray(network.allowedDomains).filter((entry) => entry !== value);
  const deniedDomains = state === "deny"
    ? dedupeStrings([...toStringArray(network.deniedDomains), value])
    : toStringArray(network.deniedDomains);

  const nextConfig = {
    ...current,
    network: {
      ...network,
      enabled: network.enabled ?? true,
      allowedDomains,
      deniedDomains,
    },
  };
  if (!writeConfigFile(configPath, nextConfig, workspaceRoot)) {
    throw new Error(`Failed to persist network grant at '${configPath}'.`);
  }
  return nextConfig;
}

export function persistSandboxNetworkGrantToConfig(
  configPath: string,
  workspaceRoot?: string,
): JsonObject {
  const targetPath = workspaceRoot
    ? resolveConfinedConfigPath(configPath, workspaceRoot)
    : configPath;
  const current = readConfigForWrite(targetPath);
  if (!current) throw new Error(`Failed to read sandbox config at '${configPath}'.`);
  const sandbox = requireConfigObject(current.sandbox, "sandbox");
  const nextConfig = {
    ...current,
    sandbox: {
      ...sandbox,
      network: true,
    },
  };
  if (!writeConfigFile(configPath, nextConfig, workspaceRoot)) {
    throw new Error(`Failed to persist sandbox network capability at '${configPath}'.`);
  }
  return nextConfig;
}

export function removeSandboxNetworkGrantFromConfig(
  configPath: string,
  workspaceRoot?: string,
): JsonObject {
  const targetPath = workspaceRoot
    ? resolveConfinedConfigPath(configPath, workspaceRoot)
    : configPath;
  const current = readConfigForWrite(targetPath);
  if (!current) throw new Error(`Failed to read sandbox config at '${configPath}'.`);
  const sandbox = requireConfigObject(current.sandbox, "sandbox");
  const nextSandbox = { ...sandbox } as JsonObject;
  delete nextSandbox.network;
  const nextConfig = { ...current, sandbox: nextSandbox };
  if (!writeConfigFile(configPath, nextConfig, workspaceRoot)) {
    throw new Error(`Failed to revoke sandbox network capability at '${configPath}'.`);
  }
  return nextConfig;
}

export function removeNetworkGrantFromConfig(
  configPath: string,
  domain: string,
  workspaceRoot?: string,
): JsonObject {
  const targetPath = workspaceRoot
    ? resolveConfinedConfigPath(configPath, workspaceRoot)
    : configPath;
  const current = readConfigForWrite(targetPath);
  if (!current) throw new Error(`Failed to read network config at '${configPath}'.`);
  const network = requireConfigObject(current.network, "network");
  const value = domain.trim();
  if (!value) return current;
  const nextConfig = {
    ...current,
    network: {
      ...network,
      allowedDomains: toStringArray(network.allowedDomains).filter((entry) => entry !== value),
    },
  };
  if (!writeConfigFile(configPath, nextConfig, workspaceRoot)) {
    throw new Error(`Failed to revoke network grant at '${configPath}'.`);
  }
  return nextConfig;
}

export function persistSandboxPathGrantToConfig(
  configPath: string,
  targetPath: string,
  mode: "ro" | "rw",
  workspaceRoot?: string,
): JsonObject {
  const configTargetPath = workspaceRoot
    ? resolveConfinedConfigPath(configPath, workspaceRoot)
    : configPath;
  const current = readConfigForWrite(configTargetPath);
  if (!current) throw new Error(`Failed to read sandbox config at '${configPath}'.`);
  const sandbox = requireConfigObject(current.sandbox, "sandbox");
  const roBinds = toStringArray(sandbox.roBinds);
  const rwBinds = toStringArray(sandbox.rwBinds);
  const value = targetPath.trim();

  const nextSandbox = {
    ...sandbox,
  } as JsonObject;
  const nextRoBinds = mode === "ro"
    ? dedupeStrings([...roBinds, value])
    : roBinds.filter((entry) => entry !== value);
  const nextRwBinds = mode === "rw"
    ? dedupeStrings([...rwBinds, value])
    : rwBinds.filter((entry) => entry !== value);
  if (nextRoBinds.length > 0) nextSandbox.roBinds = nextRoBinds;
  if (nextRwBinds.length > 0) nextSandbox.rwBinds = nextRwBinds;

  const nextConfig = {
    ...current,
    sandbox: nextSandbox,
  };
  if (!writeConfigFile(configPath, nextConfig, workspaceRoot)) {
    throw new Error(`Failed to persist sandbox path grant at '${configPath}'.`);
  }
  return nextConfig;
}

export function removeSandboxPathGrantFromConfig(
  configPath: string,
  targetPath: string,
  workspaceRoot?: string,
): JsonObject {
  const configTargetPath = workspaceRoot
    ? resolveConfinedConfigPath(configPath, workspaceRoot)
    : configPath;
  const current = readConfigForWrite(configTargetPath);
  if (!current) throw new Error(`Failed to read sandbox config at '${configPath}'.`);
  const sandbox = requireConfigObject(current.sandbox, "sandbox");
  const value = targetPath.trim();
  if (!value) return current;
  const nextSandbox = { ...sandbox } as JsonObject;
  const roBinds = toStringArray(sandbox.roBinds).filter((entry) => entry !== value);
  const rwBinds = toStringArray(sandbox.rwBinds).filter((entry) => entry !== value);
  if (roBinds.length > 0) nextSandbox.roBinds = roBinds;
  else delete nextSandbox.roBinds;
  if (rwBinds.length > 0) nextSandbox.rwBinds = rwBinds;
  else delete nextSandbox.rwBinds;
  const nextConfig = { ...current, sandbox: nextSandbox };
  if (!writeConfigFile(configPath, nextConfig, workspaceRoot)) {
    throw new Error(`Failed to revoke sandbox path grant at '${configPath}'.`);
  }
  return nextConfig;
}
