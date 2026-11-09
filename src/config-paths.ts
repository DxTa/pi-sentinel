import { join } from "node:path";

const EXTENSION_ID = "pi-sentinel";

export const DEBUG_LOG_FILENAME = `${EXTENSION_ID}-debug.jsonl`;
export const REVIEW_LOG_FILENAME = `${EXTENSION_ID}-permission-review.jsonl`;

export function getGlobalConfigDir(agentDir: string): string {
  return join(agentDir, "extensions", EXTENSION_ID);
}

export function getBundledConfigPath(extensionRoot: string): string {
  return join(extensionRoot, "config.json");
}

export function getGlobalConfigPath(agentDir: string): string {
  return join(agentDir, "sentinel.json");
}

export function getGlobalLogsDir(agentDir: string): string {
  return join(getGlobalConfigDir(agentDir), "logs");
}

export function getProjectConfigPath(cwd: string): string {
  return join(cwd, ".pi", "sentinel.json");
}

/** Retired file detected only to warn the user; never read. */
export function getRetiredGlobalConfigPath(agentDir: string): string {
  return join(agentDir, "permissions.json");
}

/** Retired file detected only to warn the user; never read. */
export function getRetiredProjectConfigPath(cwd: string): string {
  return join(cwd, ".pi", "permissions.json");
}
