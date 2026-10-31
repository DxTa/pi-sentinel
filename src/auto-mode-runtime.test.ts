import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { loadInferenceRuntime } from "./auto-mode-model";

// Minimal ONNX graph: y = x + [10, 20, 30] (float32 [1, 3], opset 13).
const ADD_MODEL_BASE64 =
  "CAg6WQoOCgF4CgF3EgF5IgNBZGQSBHRpbnkqFwgBCAMQASIMAAAgQQAAoEEAAPBBQgF3WhMKAXgSDgoMCAESCAoCCAEKAggDYhMKAXkSDgoMCAESCAoCCAEKAggDQgQKABAN";

// auto mode depends on these shipping with the extension. Run real CPU
// inference so a missing or broken ONNX Runtime install fails the suite.
describe("auto mode inference runtime", () => {
  it("loads ONNX Runtime and the tokenizer library and runs a model on CPU", async () => {
    const { ort, transformers } = await loadInferenceRuntime();
    expect(typeof transformers.AutoTokenizer.from_pretrained).toBe("function");

    const dir = mkdtempSync(join(tmpdir(), "pi-onnx-runtime-"));
    try {
      const modelPath = join(dir, "add.onnx");
      writeFileSync(modelPath, Buffer.from(ADD_MODEL_BASE64, "base64"));
      const session = await ort.InferenceSession.create(modelPath, { executionProviders: ["cpu"] });
      try {
        const output = await session.run({
          x: new ort.Tensor("float32", Float32Array.from([1, 2, 3]), [1, 3]),
        });
        expect(Array.from(output.y.data as Float32Array)).toEqual([11, 22, 33]);
      } finally {
        await session.release();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
