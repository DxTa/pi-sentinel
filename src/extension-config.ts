import { existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { toRecord } from "./common";

export const EXTENSION_ID = "pi-sentinel";

export type PermissionMode = "manual" | "yolo" | "yolo-auto";

/** Where an explicit mode choice is stored. */
export type ModeScope = "session" | "project" | "global";

export interface PermissionSystemExtensionConfig {
  debugLog: boolean;
  permissionReviewLog: boolean;
  /** Permission approval mode. yolo-auto uses model flow for eligible reads/lists and classic bypass elsewhere. */
  mode: PermissionMode;
  /** Bash command patterns that still prompt in yolo and yolo-auto modes. */
  yoloAskBashPatterns: string[];
  /** Additional directories to auto-allow for reads as Pi infrastructure. */
  piInfrastructureReadPaths?: string[];
}

export const DEFAULT_EXTENSION_CONFIG: PermissionSystemExtensionConfig = {
  debugLog: false,
  permissionReviewLog: true,
  mode: "yolo-auto",
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
      record.mode === "manual" || record.mode === "yolo" || record.mode === "yolo-auto"
        ? record.mode
        : record.yoloAutoMode === true
          ? "yolo-auto"
          : record.yoloMode === true
            ? "yolo"
            : "manual",
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
