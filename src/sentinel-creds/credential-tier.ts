/**
 * Credential sensitivity tiers for model auto-approval (D15).
 * Low tier = test/local-dev secrets or low-confidence heuristic matches.
 * Anything unrecognized is high tier and must prompt.
 */
import type { ScanMatch } from "./scanner.js";

const LOW_CONFIDENCE_LABELS = new Set([
  "Generic Secret",
  "Generic Secret (unquoted)",
  "Env Assignment (quoted)",
  "High-Entropy Value",
  "generic-api-key",
]);
const STRIPE_TEST_VALUE = /^[sr]k_test_/;
const LOCAL_DB_HOST = /@(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:[/?#]|$)/i;

export function isLowTierMatch(match: ScanMatch): boolean {
  if (LOW_CONFIDENCE_LABELS.has(match.label)) return true;
  const value = match.value ?? "";
  if (STRIPE_TEST_VALUE.test(value)) return true;
  return match.label === "Database URL with password" && LOCAL_DB_HOST.test(value);
}

export function allMatchesLowTier(matches: readonly ScanMatch[]): boolean {
  return matches.length > 0 && matches.every(isLowTierMatch);
}
