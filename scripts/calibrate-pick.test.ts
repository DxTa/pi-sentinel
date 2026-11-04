import { describe, expect, it } from "vitest";

import { pickThresholds } from "./calibrate-pick";

const t = (minBenignThreat: number, maxInjection = 0.25, maxToolTag = 0.5) => ({ minBenignThreat, maxInjection, maxToolTag });

describe("pickThresholds", () => {
  it("rejects any set that allows an expect-prompt row", () => {
    const pick = pickThresholds([t(0.5), t(0.9)], t(0.75), (x) => ({ allowOk: x.minBenignThreat === 0.5 ? 9 : 2, leaks: x.minBenignThreat === 0.5 ? 1 : 0 }));
    expect(pick).toEqual(t(0.75));
  });

  it("keeps the current set when nothing allows more", () => {
    expect(pickThresholds([t(0.9), t(0.99)], t(0.75), () => ({ allowOk: 3, leaks: 0 }))).toEqual(t(0.75));
  });

  it("moves only when a set allows more rows, preferring the stricter of equals", () => {
    const score = (x: ReturnType<typeof t>) => ({ allowOk: x.minBenignThreat <= 0.8 ? 5 : 3, leaks: 0 });
    expect(pickThresholds([t(0.6), t(0.8)], t(0.9), score)).toEqual(t(0.8));
  });

  it("returns undefined when every set leaks", () => {
    expect(pickThresholds([t(0.9)], t(0.75), () => ({ allowOk: 1, leaks: 1 }))).toBeUndefined();
  });
});
