/**
 * Network domain gate configuration loader.
 * Loads from the layered permission config network section.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import type { DomainGateConfig, ResolvedDomainPolicy } from "./types.js";
import { getSessionDomainGrants } from "./session-domains.js";

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
 * Resolve domain gate policy from the unified config's network section,
 * with session grants layered on top (deny wins at match time).
 */
export function loadDomainPolicy(
  config: { network?: DomainGateConfig } | undefined,
): ResolvedDomainPolicy {
  const base = config?.network && Object.keys(config.network).length > 0
    ? mergeDomainConfigs(DEFAULT_DOMAIN_POLICY, config.network)
    : { ...DEFAULT_DOMAIN_POLICY };
  const session = getSessionDomainGrants();
  return {
    ...base,
    allowedDomains: [...base.allowedDomains, ...session.allowed],
    deniedDomains: [...base.deniedDomains, ...session.denied],
  };
}

export { DEFAULT_DOMAIN_POLICY, getAgentDir };