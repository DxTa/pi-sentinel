import { existsSync, readFileSync } from "node:fs";
import { isPermissionState, toRecord } from "./common";
import {
  getBundledConfigPath,
  getGlobalConfigPath,
  getLegacyGlobalPolicyPath,
  getLegacyProjectConfigPath,
  getLegacyProjectExtensionConfigPath,
  getLegacyProjectPolicyPath,
  getProjectConfigPath,
} from "./config-paths";
import { mergeFlatPermissions } from "./permission-merge";
import { parsePermissionMode, type PermissionMode } from "./extension-config";
import type { FlatPermissionConfig } from "./types";

/**
 * Unified config shape combining runtime knobs and flat permission policy.
 * All fields are optional so partial configs (project-only, global-only) work.
 */
const REMOVED_AUTO_MODE_MAX_LEVEL_WARNING =
  "'yoloAutoMaxLevel' is no longer supported; auto uses fixed model thresholds.";

export function stripLegacyAutoModeMaxLevel(config: Record<string, unknown>): void {
  delete config.yoloAutoMaxLevel;
}

export interface UnifiedPermissionConfig {
  // Runtime knobs
  debugLog?: boolean;
  permissionReviewLog?: boolean;
  mode?: PermissionMode;
  yoloAskBashPatterns?: string[];

  // Flat permission policy
  permission?: FlatPermissionConfig;
}

export interface LegacyModeFlags {
  yoloMode?: boolean;
  yoloAutoMode?: boolean;
}

export interface UnifiedConfigLoadResult {
  config: UnifiedPermissionConfig;
  issues: string[];
  legacyMode?: LegacyModeFlags;
}

export function stripJsonComments(input: string): string {
  let output = "";
  let inString = false;
  let stringQuote: '"' | "'" | "" = "";
  let escaping = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    const next = input[i + 1] || "";

    if (inLineComment) {
      if (char === "\n") {
        inLineComment = false;
        output += char;
      }
      continue;
    }

    if (inBlockComment) {
      if (char === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (!inString && char === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }

    if (!inString && char === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }

    output += char;

    if (!inString && (char === '"' || char === "'")) {
      inString = true;
      stringQuote = char;
      escaping = false;
      continue;
    }

    if (!inString) {
      continue;
    }

    if (escaping) {
      escaping = false;
      continue;
    }

    if (char === "\\") {
      escaping = true;
      continue;
    }

    if (char === stringQuote) {
      inString = false;
      stringQuote = "";
    }
  }

  return output;
}

function normalizeOptionalBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  return undefined;
}

function normalizeOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  return value
    .filter((entry): entry is string => typeof entry === "string")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/**
 * Normalize a raw `permission` value from parsed JSON into a FlatPermissionConfig.
 * Drops non-object top-level values, invalid PermissionState strings, and
 * invalid action values inside object maps.
 */
function normalizeFlatPermissionValue(
  value: unknown,
): FlatPermissionConfig | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const normalized: FlatPermissionConfig = {};
  let hasAny = false;

  for (const [key, val] of Object.entries(record)) {
    if (typeof val === "string") {
      if (isPermissionState(val)) {
        normalized[key] = val;
        hasAny = true;
      }
    } else if (typeof val === "object" && val !== null && !Array.isArray(val)) {
      const map: Record<string, import("./types").PermissionState> = {};
      let mapHasAny = false;
      for (const [pattern, action] of Object.entries(
        val as Record<string, unknown>,
      )) {
        if (isPermissionState(action)) {
          map[pattern] = action;
          mapHasAny = true;
        }
      }
      if (mapHasAny) {
        normalized[key] = map;
        hasAny = true;
      }
    }
  }

  return hasAny ? normalized : undefined;
}

/**
 * Normalize raw parsed JSON into the unified config shape.
 */
export function normalizeUnifiedConfig(raw: unknown): UnifiedConfigLoadResult {
  const record = toRecord(raw);
  const issues: string[] = [];
  const config: UnifiedPermissionConfig = {};
  if (Object.hasOwn(record, "yoloAutoMaxLevel")) {
    issues.push(REMOVED_AUTO_MODE_MAX_LEVEL_WARNING);
  }

  // Runtime knobs
  const debugLog = normalizeOptionalBoolean(record.debugLog);
  if (debugLog !== undefined) config.debugLog = debugLog;

  const permissionReviewLog = normalizeOptionalBoolean(
    record.permissionReviewLog,
  );
  if (permissionReviewLog !== undefined)
    config.permissionReviewLog = permissionReviewLog;

  const parsedMode = parsePermissionMode(record.mode);
  const explicitMode = parsedMode !== undefined;
  if (record.mode !== undefined && !explicitMode) {
    issues.push(`Ignoring invalid mode ${JSON.stringify(record.mode)}; expected 'manual', 'yolo', or 'auto'.`);
  }
  const legacyMode: LegacyModeFlags = {};
  const yoloMode = normalizeOptionalBoolean(record.yoloMode);
  const yoloAutoMode = normalizeOptionalBoolean(record.yoloAutoMode);
  if (!explicitMode && yoloMode !== undefined) legacyMode.yoloMode = yoloMode;
  if (!explicitMode && yoloAutoMode !== undefined) legacyMode.yoloAutoMode = yoloAutoMode;

  if (explicitMode) {
    config.mode = parsedMode;
  } else if (yoloAutoMode === true) {
    config.mode = "auto";
  } else if (yoloMode === true) {
    config.mode = "yolo";
  } else if (yoloAutoMode !== undefined || yoloMode !== undefined) {
    config.mode = "manual";
  }

  const yoloAskBashPatterns = normalizeOptionalStringArray(
    record.yoloAskBashPatterns,
  );
  if (yoloAskBashPatterns !== undefined) {
    config.yoloAskBashPatterns = yoloAskBashPatterns;
  }

  // Flat permission policy
  const permission = normalizeFlatPermissionValue(record.permission);
  if (permission !== undefined) config.permission = permission;

  return {
    config,
    issues,
    ...(Object.keys(legacyMode).length > 0 ? { legacyMode } : {}),
  };
}

function legacyFlagsForMode(mode: PermissionMode | undefined): LegacyModeFlags {
  if (mode === "auto") return { yoloMode: true, yoloAutoMode: true };
  if (mode === "yolo") return { yoloMode: true, yoloAutoMode: false };
  if (mode === "manual") return { yoloMode: false, yoloAutoMode: false };
  return {};
}

function mergeLoadedConfig(
  base: UnifiedPermissionConfig,
  override: UnifiedConfigLoadResult,
): UnifiedPermissionConfig {
  const merged = mergeUnifiedConfigs(base, override.config);
  if (!override.legacyMode) return merged;

  const effective = {
    ...legacyFlagsForMode(base.mode),
    ...override.legacyMode,
  };
  if (effective.yoloAutoMode === true) {
    merged.mode = "auto";
  } else if (effective.yoloMode === true) {
    merged.mode = "yolo";
  } else {
    merged.mode = "manual";
  }
  return merged;
}

/**
 * Merge two unified configs.
 * - `permission` is deep-shallow merged (surface-level object maps are shallow-merged).
 * - Runtime knob fields (debugLog, permissionReviewLog, mode,
 *   yoloAskBashPatterns) are replaced when present in the override.
 */
export function mergeUnifiedConfigs(
  base: UnifiedPermissionConfig,
  override: UnifiedPermissionConfig,
): UnifiedPermissionConfig {
  const merged: UnifiedPermissionConfig = {};

  // Runtime knobs: override replaces base when defined
  if (override.debugLog !== undefined || base.debugLog !== undefined) {
    merged.debugLog = override.debugLog ?? base.debugLog;
  }
  if (
    override.permissionReviewLog !== undefined
    || base.permissionReviewLog !== undefined
  ) {
    merged.permissionReviewLog =
      override.permissionReviewLog ?? base.permissionReviewLog;
  }
  if (override.mode !== undefined || base.mode !== undefined) {
    merged.mode = override.mode ?? base.mode;
  }
  if (
    override.yoloAskBashPatterns !== undefined
    || base.yoloAskBashPatterns !== undefined
  ) {
    merged.yoloAskBashPatterns =
      override.yoloAskBashPatterns ?? base.yoloAskBashPatterns;
  }

  // Permission: deep-shallow merge
  const basePerm = base.permission;
  const overridePerm = override.permission;
  if (basePerm && overridePerm) {
    merged.permission = mergeFlatPermissions(basePerm, overridePerm);
  } else if (basePerm) {
    merged.permission = basePerm;
  } else if (overridePerm) {
    merged.permission = overridePerm;
  }

  return merged;
}

export type ModeLayerId =
  | "session"
  | "environment"
  | "project"
  | "project-policy-legacy"
  | "project-extension-legacy"
  | "project-config-legacy"
  | "global"
  | "global-policy-legacy"
  | "bundled";

export interface ConfigModeLayer {
  id: ModeLayerId;
  name: string;
  mode?: PermissionMode;
  legacyMode?: LegacyModeFlags;
  path: string;
  error?: "unreadable";
}

export interface MergedConfigResult {
  global: UnifiedPermissionConfig;
  project: UnifiedPermissionConfig;
  merged: UnifiedPermissionConfig;
  /** Merged file-config mode before the process-local environment override. */
  configuredMode: PermissionMode | undefined;
  modeSource: ModeLayerId;
  modeLayers: ConfigModeLayer[];
  issues: string[];
}

/**
 * Load global and project configs from the new layout, detect legacy files,
 * merge everything, and collect issues.
 *
 * Merge order:
 * 1. Bundled extension defaults — lowest precedence
 * 2. Legacy global policy (if present)
 * 3. New global permissions.json
 * 4. Legacy project policy and extension config (if present)
 * 5. Legacy project `.pi/agent/permissions.json` compatibility layer
 * 6. Project `.pi/permissions.json` — highest precedence
 *
 * Bundled config is never treated as a legacy file. Legacy-format keys
 * (defaultPolicy, tools, bash, etc.) are not translated and contribute no
 * permission rules; warnings do not suggest a destructive blind move.
 */
export function loadAndMergeConfigs(
  agentDir: string,
  cwd: string | null,
  extensionRoot: string,
): MergedConfigResult {
  const allIssues: string[] = [];

  const bundledPath = getBundledConfigPath(extensionRoot);
  const newGlobalPath = getGlobalConfigPath(agentDir);
  const projectRoot = cwd || null;
  const newProjectPath = getProjectConfigPath(projectRoot ?? "");
  const legacyProjectConfigPath = getLegacyProjectConfigPath(projectRoot ?? "");
  const legacyGlobalPolicyPath = getLegacyGlobalPolicyPath(agentDir);
  const legacyProjectPolicyPath = getLegacyProjectPolicyPath(projectRoot ?? "");
  const legacyProjectExtensionPath = getLegacyProjectExtensionConfigPath(projectRoot ?? "");

  let merged: UnifiedPermissionConfig = {};
  let modeSource: ModeLayerId = "bundled";
  const modeLayers: ConfigModeLayer[] = [];
  const mergeLayer = (
    id: ModeLayerId,
    name: string,
    filePath: string,
    result: UnifiedConfigLoadResult,
    includeWhenUnset = true,
  ): void => {
    const unreadable = result.issues.some((issue) =>
      issue.startsWith("Failed to read config at '" + filePath + "'")
    );
    const hasCompleteLegacyFlags =
      result.legacyMode?.yoloMode !== undefined &&
      result.legacyMode.yoloAutoMode !== undefined;
    const hasConfiguredMode = result.config.mode !== undefined || result.legacyMode !== undefined;
    if (includeWhenUnset || hasConfiguredMode || unreadable) {
      modeLayers.push({
        id,
        name,
        mode: result.legacyMode && !hasCompleteLegacyFlags ? undefined : result.config.mode,
        ...(result.legacyMode ? { legacyMode: result.legacyMode } : {}),
        path: filePath,
        ...(unreadable ? { error: "unreadable" } : {}),
      });
    }

    const modeBeforeLayer = merged.mode;
    merged = mergeLoadedConfig(merged, result);
    const legacyModeIsDecisive =
      result.legacyMode?.yoloAutoMode === true || hasCompleteLegacyFlags;
    const legacyModeChangedValue = merged.mode !== modeBeforeLayer;
    if (
      result.legacyMode
        ? legacyModeIsDecisive || legacyModeChangedValue
        : result.config.mode !== undefined
    ) {
      modeSource = id;
    }
  };

  // Bundled defaults are a real config layer, not a legacy user file.
  if (existsSync(bundledPath)) {
    const bundled = loadUnifiedConfig(bundledPath);
    allIssues.push(...bundled.issues);
    mergeLayer("bundled", "bundled", bundledPath, bundled);
  } else {
    allIssues.push(`Bundled permission config missing at '${bundledPath}'.`);
  }

  if (existsSync(legacyGlobalPolicyPath)) {
    const legacy = loadUnifiedConfig(legacyGlobalPolicyPath);
    allIssues.push(
      `Legacy global policy found at '${legacyGlobalPolicyPath}'. ` +
        `Legacy-format keys are not translated; leave this file unchanged and migrate supported unified keys manually to '${newGlobalPath}'.`,
    );
    allIssues.push(...legacy.issues);
    mergeLayer("global-policy-legacy", "global (legacy)", legacyGlobalPolicyPath, legacy, false);
  }

  const globalResult = loadUnifiedConfig(newGlobalPath);
  allIssues.push(...globalResult.issues);
  const globalConfig = globalResult.config;
  mergeLayer("global", "global", newGlobalPath, globalResult);

  if (projectRoot && existsSync(legacyProjectPolicyPath)) {
    const legacy = loadUnifiedConfig(legacyProjectPolicyPath);
    allIssues.push(
      `Legacy project policy found at '${legacyProjectPolicyPath}'. ` +
        `Legacy-format keys are not translated; leave this file unchanged and migrate supported unified keys manually to '${newProjectPath}'.`,
    );
    allIssues.push(...legacy.issues);
    mergeLayer("project-policy-legacy", "project (legacy)", legacyProjectPolicyPath, legacy, false);
  }

  if (projectRoot && existsSync(legacyProjectExtensionPath)) {
    const legacy = loadUnifiedConfig(legacyProjectExtensionPath);
    allIssues.push(
      `Legacy project extension config found at '${legacyProjectExtensionPath}'. ` +
        `Move supported unified settings to '${newProjectPath}' without modifying bundled defaults.`,
    );
    allIssues.push(...legacy.issues);
    mergeLayer("project-extension-legacy", "project (legacy)", legacyProjectExtensionPath, legacy, false);
  }

  let legacyProjectResult: UnifiedConfigLoadResult = { config: {}, issues: [] };
  let projectResult: UnifiedConfigLoadResult = { config: {}, issues: [] };
  if (projectRoot) {
    legacyProjectResult = loadUnifiedConfig(legacyProjectConfigPath);
    allIssues.push(...legacyProjectResult.issues);
    mergeLayer("project-config-legacy", "project (legacy)", legacyProjectConfigPath, legacyProjectResult, false);

    projectResult = loadUnifiedConfig(newProjectPath);
    allIssues.push(...projectResult.issues);
    mergeLayer("project", "project", newProjectPath, projectResult);
  }
  const projectConfig = mergeLoadedConfig(legacyProjectResult.config, projectResult);
  const configuredMode = merged.mode;

  const modeOverride = normalizeUnifiedConfig({
    mode: process.env.PI_SENTINEL_MODE,
  }).config.mode;
  modeLayers.push({ id: "environment", name: "env", mode: modeOverride, path: "PI_SENTINEL_MODE" });
  if (modeOverride !== undefined) {
    merged.mode = modeOverride;
    modeSource = "environment";
  } else if (process.env.PI_SENTINEL_MODE !== undefined) {
    allIssues.push("Ignoring invalid PI_SENTINEL_MODE; expected 'manual', 'yolo', or 'auto'.");
  }

  return {
    global: globalConfig,
    project: projectConfig,
    merged,
    configuredMode,
    modeSource,
    modeLayers: modeLayers.reverse(),
    issues: [...new Set(allIssues)],
  };
}

/**
 * Load and normalize a unified config file.
 * Returns an empty config with no issues if the file does not exist.
 * Returns an empty config with an issue if the file cannot be parsed.
 */
export function loadUnifiedConfig(path: string): UnifiedConfigLoadResult {
  if (!existsSync(path)) {
    return { config: {}, issues: [] };
  }

  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = JSON.parse(stripJsonComments(raw)) as unknown;
    return normalizeUnifiedConfig(parsed);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      config: {},
      issues: [`Failed to read config at '${path}': ${message}`],
    };
  }
}
