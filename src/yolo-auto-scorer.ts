/**
 * Per-scope logistic scorer over head features, trained on human decisions (D16).
 * Deterministic full-batch gradient descent; runs only with two-class history.
 */
export interface LabelledSample {
  features: number[];
  label: 0 | 1;
}

export interface LogisticModel {
  weights: number[];
  bias: number;
  predict(features: number[]): number;
}

export interface ScorerResult {
  probability: number;
  samples: number;
  positives: number;
  negatives: number;
}

export const MIN_SCORER_SAMPLES = 20;
export const MIN_SCORER_CLASS_SAMPLES = 3;

const sigmoid = (z: number): number => 1 / (1 + Math.exp(-z));

export function trainLogistic(
  samples: readonly LabelledSample[],
  { epochs = 300, learningRate = 0.5, l2 = 0.001 } = {},
): LogisticModel {
  const dim = samples[0]?.features.length ?? 0;
  const weights = new Array<number>(dim).fill(0);
  let bias = 0;
  for (let epoch = 0; epoch < epochs; epoch++) {
    const grad = new Array<number>(dim).fill(0);
    let gradBias = 0;
    for (const { features, label } of samples) {
      const err = sigmoid(bias + features.reduce((s, x, i) => s + x * weights[i]!, 0)) - label;
      for (let i = 0; i < dim; i++) grad[i]! += err * features[i]!;
      gradBias += err;
    }
    for (let i = 0; i < dim; i++) weights[i] = weights[i]! - learningRate * (grad[i]! / samples.length + l2 * weights[i]!);
    bias -= learningRate * (gradBias / samples.length);
  }
  const predict = (features: number[]): number =>
    sigmoid(bias + features.reduce((s, x, i) => s + x * (weights[i] ?? 0), 0));
  return { weights, bias, predict };
}

export function scoreWithHistory(
  samples: readonly LabelledSample[],
  features: number[],
): ScorerResult | undefined {
  const positives = samples.filter((s) => s.label === 1).length;
  const negatives = samples.length - positives;
  if (samples.length < MIN_SCORER_SAMPLES
    || positives < MIN_SCORER_CLASS_SAMPLES
    || negatives < MIN_SCORER_CLASS_SAMPLES) {
    return undefined;
  }
  return {
    probability: trainLogistic(samples).predict(features),
    samples: samples.length,
    positives,
    negatives,
  };
}
