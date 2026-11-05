import type { AutoModeThresholds } from "../src/auto-mode-profile.ts";

export interface Counts { allowOk: number; leaks: number }

/**
 * Choose thresholds for one operation: zero expect-prompt rows allowed, then the most expect-allow rows.
 * The current set wins ties, so calibration changes nothing it cannot improve; other ties go to the stricter set.
 * Returns undefined when no candidate is leak-free.
 */
export function pickThresholds(
  candidates: readonly AutoModeThresholds[],
  current: AutoModeThresholds,
  score: (t: AutoModeThresholds) => Counts,
): AutoModeThresholds | undefined {
  const strictness = (t: AutoModeThresholds) => t.minBenignThreat - t.maxInjection - t.maxToolTag;
  let best: { t: AutoModeThresholds; allowOk: number } | undefined;
  for (const t of [current, ...candidates]) {
    const { allowOk, leaks } = score(t);
    if (leaks > 0) continue;
    if (!best || allowOk > best.allowOk || (allowOk === best.allowOk && best.t !== current && strictness(t) > strictness(best.t))) {
      best = { t, allowOk };
    }
  }
  return best?.t;
}
