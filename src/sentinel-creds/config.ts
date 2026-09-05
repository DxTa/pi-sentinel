/**
 * sentinel-creds configuration types and loader.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export interface SentinelCredsConfig {
  enabled: boolean;
  readAllowedPaths: string[];
  /** Scan bash commands that read files (cat, head, tail, etc.). */
  scanBashReads: boolean;
  /** Block/restrict env-dumping bash commands. */
  envShield: boolean;
  /** Scan tool results for secrets and redact. */
  resultScanning: boolean;
  /** Behavior when no UI is available (headless/subagent mode). */
  headlessMode: "block" | "warn" | "allow";
  /** Env var prefixes considered safe to read. */
  safeEnvPrefixes: string[];
  /** Append-only JSONL audit log path. */
  auditLogPath: string;
  /** Persistent whitelist TTL in hours. */
  whitelistTtlHours: number;
  /** If true, allowed/whitelisted reads get raw (unredacted) output. */
  allowRawReveal: boolean;
}

export const DEFAULTS: SentinelCredsConfig = {
  enabled: true,
  readAllowedPaths: [],
  scanBashReads: true,
  envShield: true,
  resultScanning: true,
  headlessMode: "block",
  safeEnvPrefixes: [],
  auditLogPath: join(getAgentDir(), "sentinel-creds-audit.jsonl"),
  whitelistTtlHours: 24,
  allowRawReveal: false,
};

function getAgentDir(): string {
  const envDir = process.env.PI_CODING_AGENT_DIR;
  if (!envDir) return join(homedir(), ".pi", "agent");
  if (envDir === "~") return homedir();
  if (envDir.startsWith("~/")) return join(homedir(), envDir.slice(2));
  return envDir;
}

function expandConfigPath(pathValue: string): string {
  if (pathValue === "~") return homedir();
  if (pathValue.startsWith("~/")) return join(homedir(), pathValue.slice(2));
  return pathValue;
}

/**
 * Load sentinel-creds config from pi-sentinel config.json `sentinelCreds` key.
 * Falls back to legacy standalone sentinel-creds.json if key is missing.
 */
export function loadSentinelCredsConfig(
  mainConfig?: { sentinelCreds?: Partial<SentinelCredsConfig> },
): SentinelCredsConfig {
  const raw = mainConfig?.sentinelCreds;
  if (raw) {
    return mergeWithDefaults(raw);
  }

  // Legacy fallback: standalone sentinel-creds.json
  const legacyPath = join(getAgentDir(), "extensions", "sentinel-creds.json");
  try {
    if (existsSync(legacyPath)) {
      const parsed = JSON.parse(readFileSync(legacyPath, "utf-8")) as Partial<SentinelCredsConfig>;
      return mergeWithDefaults(parsed);
    }
  } catch { /* fall through */ }

  return { ...DEFAULTS };
}

function mergeWithDefaults(raw: Partial<SentinelCredsConfig>): SentinelCredsConfig {
  return {
    enabled: raw.enabled ?? DEFAULTS.enabled,
    readAllowedPaths: raw.readAllowedPaths ?? DEFAULTS.readAllowedPaths,
    scanBashReads: raw.scanBashReads ?? DEFAULTS.scanBashReads,
    envShield: raw.envShield ?? DEFAULTS.envShield,
    resultScanning: raw.resultScanning ?? DEFAULTS.resultScanning,
    headlessMode: raw.headlessMode ?? DEFAULTS.headlessMode,
    safeEnvPrefixes: raw.safeEnvPrefixes ?? DEFAULTS.safeEnvPrefixes,
    auditLogPath: expandConfigPath(raw.auditLogPath ?? DEFAULTS.auditLogPath),
    whitelistTtlHours: raw.whitelistTtlHours ?? DEFAULTS.whitelistTtlHours,
    allowRawReveal: raw.allowRawReveal ?? DEFAULTS.allowRawReveal,
  };
}
