import { existsSync, readFileSync } from "node:fs";
import { isPermissionState, toRecord } from "./common";
import {
  getBundledConfigPath,
  getGlobalConfigPath,
  getProjectConfigPath,
  getRetiredGlobalConfigPath,
  getRetiredProjectConfigPath,
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
  if (explicitMode) config.mode = parsedMode;

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

export type ModeLayerId = "session" | "environment" | "project" | "global" | "bundled";

export interface ConfigModeLayer {
  id: ModeLayerId;
  name: string;
  mode?: PermissionMode;
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
 * Load bundled, global, and project configs, merge them, and collect issues.
 *
 * Merge order (lowest → highest precedence):
 * 1. Bundled extension defaults
 * 2. Global `sentinel.json`
 * 3. Project `.pi/sentinel.json`
 *
 * Retired `permissions.json` files are never read. A warning names the rename.
 */
export function loadAndMergeConfigs(
  agentDir: string,
  cwd: string | null,
  extensionRoot: string,
): MergedConfigResult {
  const allIssues: string[] = [];

  const bundledPath = getBundledConfigPath(extensionRoot);
  const globalPath = getGlobalConfigPath(agentDir);
  const projectRoot = cwd || null;
  const projectPath = getProjectConfigPath(projectRoot ?? "");

  let merged: UnifiedPermissionConfig = {};
  let modeSource: ModeLayerId = "bundled";
  const modeLayers: ConfigModeLayer[] = [];
  const mergeLayer = (
    id: ModeLayerId,
    name: string,
    filePath: string,
    result: UnifiedConfigLoadResult,
  ): void => {
    const unreadable = result.issues.some((issue) =>
      issue.startsWith("Failed to read config at '" + filePath + "'")
    );
    modeLayers.push({
      id,
      name,
      mode: result.config.mode,
      path: filePath,
      ...(unreadable ? { error: "unreadable" as const } : {}),
    });
    merged = mergeUnifiedConfigs(merged, result.config);
    if (result.config.mode !== undefined) modeSource = id;
  };

  if (existsSync(bundledPath)) {
    const bundled = loadUnifiedConfig(bundledPath);
    allIssues.push(...bundled.issues);
    mergeLayer("bundled", "bundled", bundledPath, bundled);
  } else {
    allIssues.push(`Bundled permission config missing at '${bundledPath}'.`);
  }

  const retiredGlobalPath = getRetiredGlobalConfigPath(agentDir);
  if (!existsSync(globalPath) && existsSync(retiredGlobalPath)) {
    allIssues.push(`Retired config '${retiredGlobalPath}' is ignored; rename it to '${globalPath}'.`);
  }
  const globalResult = loadUnifiedConfig(globalPath);
  allIssues.push(...globalResult.issues);
  mergeLayer("global", "global", globalPath, globalResult);

  let projectResult: UnifiedConfigLoadResult = { config: {}, issues: [] };
  if (projectRoot) {
    const retiredProjectPath = getRetiredProjectConfigPath(projectRoot);
    if (!existsSync(projectPath) && existsSync(retiredProjectPath)) {
      allIssues.push(`Retired config '${retiredProjectPath}' is ignored; rename it to '${projectPath}'.`);
    }
    projectResult = loadUnifiedConfig(projectPath);
    allIssues.push(...projectResult.issues);
    mergeLayer("project", "project", projectPath, projectResult);
  }
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
    global: globalResult.config,
    project: projectResult.config,
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
