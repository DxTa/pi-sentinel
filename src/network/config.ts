/**
 * Network domain gate configuration loader.
 * Loads from layered permission config network section with backward-compatible domain-gate.json support.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { DomainGateConfig, ResolvedDomainPolicy } from "./types.js";

export type { DomainGateConfig, ResolvedDomainPolicy };

const DEFAULT_DOMAIN_POLICY: ResolvedDomainPolicy = {
  enabled: true,
  unknownDomains: "ask",
  allowedDomains: [],
  deniedDomains: [],
};

function getAgentDir(): string {
  return process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent");
}

/**
 * Load the legacy domain-gate.json config (backward compatibility).
 */
export function readLegacyConfig(
  globalPath: string,
  projectPath: string,
): DomainGateConfig {
  const global = readJsonFile(globalPath);
  const project = readJsonFile(projectPath);
  return { ...global, ...project };
}

function readJsonFile(path: string): DomainGateConfig {
  if (!existsSync(path)) return {};
  try {
    const parsed = JSON.parse(readFileSync(path, "utf-8")) as DomainGateConfig;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Merge domain configs: later entries override earlier.
 */
function mergeDomainConfigs(
  base: ResolvedDomainPolicy,
  override: DomainGateConfig,
): ResolvedDomainPolicy {
  return {
    enabled: override.enabled ?? base.enabled,
    unknownDomains: (override.unknownDomains !== undefined ? normalizeUnknownDomains(override.unknownDomains) : base.unknownDomains) ?? base.unknownDomains,
    allowedDomains: override.allowedDomains ?? base.allowedDomains,
    deniedDomains: override.deniedDomains ?? base.deniedDomains,
  };
}

export function normalizeUnknownDomains(
  value: boolean | string | undefined,
): "allow" | "deny" | "ask" {
  if (value === undefined) return "ask"; // default
  if (typeof value === "boolean") return value ? "allow" : "deny";
  const str = String(value).trim().toLowerCase();
  if (str === "allow" || str === "true") return "allow";
  if (str === "deny" || str === "false") return "deny";
  if (str === "ask") return "ask";
  return "ask"; // fail closed for invalid values
}

/**
 * Resolve domain gate policy from the unified config.
 * Falls back to legacy domain-gate.json if network section is absent.
 */
export function loadDomainPolicy(
  config: { network?: DomainGateConfig } | undefined,
  cwd: string,
): ResolvedDomainPolicy {
  // If unified config has network section, use it
  if (config?.network && Object.keys(config.network).length > 0) {
    return mergeDomainConfigs(DEFAULT_DOMAIN_POLICY, config.network);
  }

  // Fall back to legacy domain-gate.json
  const globalPath = join(getAgentDir(), "domain-gate.json");
  const projectPath = join(cwd, ".pi", "domain-gate.json");
  const legacyConfig = readLegacyConfig(globalPath, projectPath);

  if (Object.keys(legacyConfig).length > 0) {
    // Legacy domain-gate.json remains supported silently for local compatibility.
    // Map legacy boolean to new enum
    const mapped: DomainGateConfig = {
      enabled: legacyConfig.enabled,
      unknownDomains: legacyConfig.unknownDomains ?? ((legacyConfig as Record<string, unknown>).allowUnknownDomains === false ? "deny" : "allow"),
      allowedDomains: legacyConfig.allowedDomains,
      deniedDomains: legacyConfig.deniedDomains,
    };
    return mergeDomainConfigs(DEFAULT_DOMAIN_POLICY, mapped);
  }

  return { ...DEFAULT_DOMAIN_POLICY };
}

export { DEFAULT_DOMAIN_POLICY, getAgentDir };