/**
 * Domain matching and policy evaluation.
 * Ported from domain-gate.ts with enhanced matching.
 */

import type { DomainCheckResult, DomainVerdict, ResolvedDomainPolicy } from "./types.js";

/**
 * Check if a domain matches a pattern.
 * Supports:
 * - Exact match: "example.com"
 * - Wildcard: "*.example.com" matches "sub.example.com" and "example.com"
 * - Global wildcard: "*"
 */
export function domainMatchesPattern(domain: string, pattern: string): boolean {
  const normalized = pattern.toLowerCase();
  if (normalized === "*") return true;
  if (normalized.startsWith("*.")) {
    const base = normalized.slice(2);
    return domain === base || domain.endsWith(`.${base}`);
  }
  return domain === normalized;
}

function matchesAny(domain: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => domainMatchesPattern(domain, pattern));
}

function bestMatchSpecificity(
  domain: string,
  patterns: readonly string[],
): number | null {
  let best: number | null = null;
  for (const pattern of patterns) {
    if (!domainMatchesPattern(domain, pattern)) continue;
    const specificity = pattern.replaceAll("*", "").length;
    if (best === null || specificity > best) {
      best = specificity;
    }
  }
  return best;
}

/**
 * Check which domains are blocked by the policy.
 */
export function blockedDomains(
  domains: string[],
  policy: ResolvedDomainPolicy,
): DomainCheckResult {
  const blocked: string[] = [];
  if (!policy.enabled) {
    for (const domain of domains) {
      if (matchesAny(domain, policy.deniedDomains)) blocked.push(domain);
    }
    return {
      verdict: blocked.length > 0 ? "denied" : "allowed",
      blockedDomains: blocked,
      askDomains: [],
      reason:
        blocked.length > 0
          ? `Domain gate blocked network access to ${blocked.map((d) => `"${d}"`).join(", ")}. Remove from deniedDomains or configure network policy.`
          : undefined,
    };
  }

  const ask: string[] = [];

  for (const domain of domains) {
    const allowedSpecificity = bestMatchSpecificity(
      domain,
      policy.allowedDomains,
    );
    const deniedSpecificity = bestMatchSpecificity(
      domain,
      policy.deniedDomains,
    );

    if (deniedSpecificity !== null) {
      blocked.push(domain);
      continue;
    }
    if (allowedSpecificity !== null) {
      continue;
    }

    // Unknown domain
    if (policy.unknownDomains === "deny") {
      blocked.push(domain);
    } else if (policy.unknownDomains === "ask") {
      ask.push(domain);
    }
    // "allow" → pass through
  }

  const verdict: DomainVerdict =
    blocked.length > 0 ? "denied" : ask.length > 0 ? "ask" : "allowed";

  return {
    verdict,
    blockedDomains: blocked,
    askDomains: ask,
    reason:
      blocked.length > 0
        ? `Domain gate blocked network access to ${blocked.map((d) => `"${d}"`).join(", ")}. Remove from deniedDomains or configure network policy.`
        : undefined,
  };
}

export { bestMatchSpecificity, matchesAny };