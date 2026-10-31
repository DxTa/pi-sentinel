import { existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { toRecord } from "./common";

export const EXTENSION_ID = "pi-sentinel";

export type PermissionMode = "manual" | "yolo" | "auto";

export const PERMISSION_MODES: readonly PermissionMode[] = ["manual", "yolo", "auto"];

/** Deprecated mode names that are still read from config files and PI_SENTINEL_MODE. */
const LEGACY_MODE_ALIASES: Readonly<Record<string, PermissionMode>> = {
  "yolo-auto": "auto",
};

/** True when `value` is a deprecated mode name such as `yolo-auto`. */
export function isLegacyModeAlias(value: unknown): boolean {
  return typeof value === "string" && Object.hasOwn(LEGACY_MODE_ALIASES, value);
}

/** Parse a configured mode, mapping deprecated aliases to their current name. */
export function parsePermissionMode(value: unknown): PermissionMode | undefined {
  if (typeof value !== "string") return undefined;
  if ((PERMISSION_MODES as readonly string[]).includes(value)) return value as PermissionMode;
  return Object.hasOwn(LEGACY_MODE_ALIASES, value) ? LEGACY_MODE_ALIASES[value] : undefined;
}

/** Where an explicit mode choice is stored. */
export type ModeScope = "session" | "project" | "global";

export interface PermissionSystemExtensionConfig {
  debugLog: boolean;
  permissionReviewLog: boolean;
  /** Permission approval mode. `auto` uses the classifier for eligible workspace requests and classic yolo elsewhere. */
  mode: PermissionMode;
  /** Bash command patterns that still prompt in yolo and auto modes. */
  yoloAskBashPatterns: string[];
  /** Additional directories to auto-allow for reads as Pi infrastructure. */
  piInfrastructureReadPaths?: string[];
}

export const DEFAULT_EXTENSION_CONFIG: PermissionSystemExtensionConfig = {
  debugLog: false,
  permissionReviewLog: true,
  mode: "auto",
  yoloAskBashPatterns: [],
};

function resolveExtensionRoot(moduleUrl = import.meta.url): string {
  return join(dirname(fileURLToPath(moduleUrl)), "..");
}

export const EXTENSION_ROOT = resolveExtensionRoot();

const PERMISSION_POLICY_KEYS: ReadonlySet<string> = new Set([
  "defaultPolicy",
  "tools",
  "bash",
  "mcp",
  "skills",
  "special",
  "external_directory",
]);

export function detectMisplacedPermissionKeys(
  raw: Record<string, unknown>,
): string[] {
  return Object.keys(raw).filter((key) => PERMISSION_POLICY_KEYS.has(key));
}

export function normalizePermissionSystemConfig(
  raw: unknown,
): PermissionSystemExtensionConfig {
  const record = toRecord(raw);
  const rawPaths = record.piInfrastructureReadPaths;
  const piInfrastructureReadPaths: string[] | undefined =
    Array.isArray(rawPaths) &&
    rawPaths.every((p): p is string => typeof p === "string")
      ? rawPaths
      : undefined;
  const yoloAskBashPatterns = Array.isArray(record.yoloAskBashPatterns)
    ? record.yoloAskBashPatterns
        .filter((pattern): pattern is string => typeof pattern === "string")
        .map((pattern) => pattern.trim())
        .filter(Boolean)
    : [];
  const result: PermissionSystemExtensionConfig = {
    debugLog: record.debugLog === true,
    permissionReviewLog: record.permissionReviewLog !== false,
    mode:
      parsePermissionMode(record.mode)
        ?? (record.yoloAutoMode === true
          ? "auto"
          : record.yoloMode === true
            ? "yolo"
            : "manual"),
    yoloAskBashPatterns,
  };
  if (piInfrastructureReadPaths !== undefined) {
    result.piInfrastructureReadPaths = piInfrastructureReadPaths;
  }
  return result;
}

export function ensurePermissionSystemLogsDirectory(
  logsDir: string,
): string | undefined {
  try {
    mkdirSync(logsDir, { recursive: true });
    return undefined;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return `Failed to create pi-sentinel log directory '${logsDir}': ${message}`;
  }
}
