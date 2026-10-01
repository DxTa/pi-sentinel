import { describe, expect, it } from "vitest";

import { scoreWithHistory, trainLogistic } from "./yolo-auto-scorer";

const dim = 46;
const approveLike = (j: number) => Array.from({ length: dim }, (_, i) => (i < 10 ? 0.9 : 0.05) + (j % 3) * 0.01);
const denyLike = (j: number) => Array.from({ length: dim }, (_, i) => (i >= 10 && i < 20 ? 0.9 : 0.05) + (j % 3) * 0.01);

describe("trainLogistic", () => {
  it("separates approve-like from deny-like features deterministically", () => {
    const samples = [
      ...Array.from({ length: 15 }, (_, j) => ({ features: approveLike(j), label: 1 as const })),
      ...Array.from({ length: 6 }, (_, j) => ({ features: denyLike(j), label: 0 as const })),
    ];
    const a = trainLogistic(samples);
    const b = trainLogistic(samples);
    expect({ weights: a.weights, bias: a.bias }).toEqual({ weights: b.weights, bias: b.bias });
    expect(a.predict(approveLike(7))).toBeGreaterThan(0.97);
    expect(a.predict(denyLike(7))).toBeLessThan(0.1);
  });
});

describe("scoreWithHistory", () => {
  const approve = Array.from({ length: 17 }, (_, j) => ({ features: approveLike(j), label: 1 as const }));
  const deny = Array.from({ length: 4 }, (_, j) => ({ features: denyLike(j), label: 0 as const }));

  it("scores only when there are ≥20 samples with ≥3 of each class", () => {
    expect(scoreWithHistory([...approve, ...deny], approveLike(1))).toMatchObject({
      samples: 21, positives: 17, negatives: 4,
    });
    expect(scoreWithHistory([...approve, ...deny], approveLike(1))?.probability).toBeGreaterThan(0.97);
    expect(scoreWithHistory([...approve, ...deny.slice(0, 2)], approveLike(1))).toBeUndefined();
    expect(scoreWithHistory([...approve.slice(0, 10), ...deny], approveLike(1))).toBeUndefined();
    expect(scoreWithHistory(approve.concat(approve), approveLike(1))).toBeUndefined();
  });
});
