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
import type { FlatPermissionConfig } from "./types";

/**
 * Unified config shape combining runtime knobs and flat permission policy.
 * All fields are optional so partial configs (project-only, global-only) work.
 */
export interface UnifiedPermissionConfig {
  // Runtime knobs
  debugLog?: boolean;
  permissionReviewLog?: boolean;
  yoloMode?: boolean;
  yoloAutoMode?: boolean;
  yoloAutoMaxLevel?: "l1" | "l2" | "l3";
  yoloAskBashPatterns?: string[];

  // Flat permission policy
  permission?: FlatPermissionConfig;
}

export interface UnifiedConfigLoadResult {
  config: UnifiedPermissionConfig;
  issues: string[];
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
export function normalizeUnifiedConfig(raw: unknown): {
  config: UnifiedPermissionConfig;
  issues: string[];
} {
  const record = toRecord(raw);
  const issues: string[] = [];
  const config: UnifiedPermissionConfig = {};

  // Runtime knobs
  const debugLog = normalizeOptionalBoolean(record.debugLog);
  if (debugLog !== undefined) config.debugLog = debugLog;

  const permissionReviewLog = normalizeOptionalBoolean(
    record.permissionReviewLog,
  );
  if (permissionReviewLog !== undefined)
    config.permissionReviewLog = permissionReviewLog;

  const yoloMode = normalizeOptionalBoolean(record.yoloMode);
  if (yoloMode !== undefined) config.yoloMode = yoloMode;

  const yoloAutoMode = normalizeOptionalBoolean(record.yoloAutoMode);
  if (yoloAutoMode !== undefined) config.yoloAutoMode = yoloAutoMode;

  if (
    record.yoloAutoMaxLevel === "l1"
    || record.yoloAutoMaxLevel === "l2"
    || record.yoloAutoMaxLevel === "l3"
  ) {
    config.yoloAutoMaxLevel = record.yoloAutoMaxLevel;
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

  return { config, issues };
}

/**
 * Merge two unified configs.
 * - `permission` is deep-shallow merged (surface-level object maps are shallow-merged).
 * - Runtime knob fields (debugLog, permissionReviewLog, yoloMode,
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
  if (override.yoloMode !== undefined || base.yoloMode !== undefined) {
    merged.yoloMode = override.yoloMode ?? base.yoloMode;
  }
  if (override.yoloAutoMode !== undefined || base.yoloAutoMode !== undefined) {
    merged.yoloAutoMode = override.yoloAutoMode ?? base.yoloAutoMode;
  }
  if (override.yoloAutoMaxLevel !== undefined || base.yoloAutoMaxLevel !== undefined) {
    merged.yoloAutoMaxLevel = override.yoloAutoMaxLevel ?? base.yoloAutoMaxLevel;
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

export interface MergedConfigResult {
  global: UnifiedPermissionConfig;
  project: UnifiedPermissionConfig;
  merged: UnifiedPermissionConfig;
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
  cwd: string,
  extensionRoot: string,
): MergedConfigResult {
  const allIssues: string[] = [];

  const bundledPath = getBundledConfigPath(extensionRoot);
  const newGlobalPath = getGlobalConfigPath(agentDir);
  const newProjectPath = getProjectConfigPath(cwd);
  const legacyProjectConfigPath = getLegacyProjectConfigPath(cwd);
  const legacyGlobalPolicyPath = getLegacyGlobalPolicyPath(agentDir);
  const legacyProjectPolicyPath = getLegacyProjectPolicyPath(cwd);
  const legacyProjectExtensionPath = getLegacyProjectExtensionConfigPath(cwd);

  let merged: UnifiedPermissionConfig = {};

  // Bundled defaults are a real config layer, not a legacy user file.
  if (existsSync(bundledPath)) {
    const bundled = loadUnifiedConfig(bundledPath);
    allIssues.push(...bundled.issues);
    merged = mergeUnifiedConfigs(merged, bundled.config);
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
    merged = mergeUnifiedConfigs(merged, legacy.config);
  }

  const globalResult = loadUnifiedConfig(newGlobalPath);
  allIssues.push(...globalResult.issues);
  const globalConfig = globalResult.config;
  merged = mergeUnifiedConfigs(merged, globalConfig);

  if (existsSync(legacyProjectPolicyPath)) {
    const legacy = loadUnifiedConfig(legacyProjectPolicyPath);
    allIssues.push(
      `Legacy project policy found at '${legacyProjectPolicyPath}'. ` +
        `Legacy-format keys are not translated; leave this file unchanged and migrate supported unified keys manually to '${newProjectPath}'.`,
    );
    allIssues.push(...legacy.issues);
    merged = mergeUnifiedConfigs(merged, legacy.config);
  }

  if (existsSync(legacyProjectExtensionPath)) {
    const legacy = loadUnifiedConfig(legacyProjectExtensionPath);
    allIssues.push(
      `Legacy project extension config found at '${legacyProjectExtensionPath}'. ` +
        `Move supported unified settings to '${newProjectPath}' without modifying bundled defaults.`,
    );
    allIssues.push(...legacy.issues);
    merged = mergeUnifiedConfigs(merged, legacy.config);
  }

  const legacyProjectResult = loadUnifiedConfig(legacyProjectConfigPath);
  allIssues.push(...legacyProjectResult.issues);
  merged = mergeUnifiedConfigs(merged, legacyProjectResult.config);

  const projectResult = loadUnifiedConfig(newProjectPath);
  allIssues.push(...projectResult.issues);
  const projectConfig = mergeUnifiedConfigs(legacyProjectResult.config, projectResult.config);
  merged = mergeUnifiedConfigs(merged, projectResult.config);

  return {
    global: globalConfig,
    project: projectConfig,
    merged,
    issues: allIssues,
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
