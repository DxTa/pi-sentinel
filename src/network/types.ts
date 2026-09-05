/**
 * Network domain gate types.
 * Ported from domain-gate.ts into pi-sentinel.
 */

export interface DomainGateConfig {
  enabled?: boolean;
  /** Default "ask": prompt for domains not covered by policy. */
  unknownDomains?: "allow" | "deny" | "ask";
  allowedDomains?: string[];
  deniedDomains?: string[];
}

export interface ResolvedDomainPolicy {
  enabled: boolean;
  unknownDomains: "allow" | "deny" | "ask";
  allowedDomains: string[];
  deniedDomains: string[];
}

export type DomainVerdict = "allowed" | "denied" | "ask";

export interface DomainCheckResult {
  verdict: DomainVerdict;
  blockedDomains: string[];
  /** Unknown domains that require user approval when unknownDomains is "ask". */
  askDomains?: string[];
  reason?: string;
}