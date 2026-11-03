import { describe, expect, it } from "vitest";

import { DEFAULT_MODEL_PROFILE_ID, loadModelProfile, parseModelProfile } from "./auto-mode-profile";

const valid = () => structuredClone(loadModelProfile(DEFAULT_MODEL_PROFILE_ID)) as unknown as Record<string, unknown>;

describe("model profiles", () => {
  it("loads the default profile with the pinned revision and int8 model", () => {
    const profile = loadModelProfile(DEFAULT_MODEL_PROFILE_ID);
    expect(profile.revision).toBe("77888f617584758f904faefd6f38d4cf926f6d5d");
    expect(profile.onnxPath).toBe("onnx/int8_int4_embeddings/model.onnx");
    expect(profile.maxSequenceLength).toBe(256);
    expect(profile.logitOutputs.sensitive_document).toBe("sensitive_logits");
  });

  it("rejects ids that could leave the profiles directory", () => {
    expect(() => loadModelProfile("../config")).toThrow("Invalid model profile id");
  });

  it.each([
    ["onnxPath", "../../etc/passwd"],
    ["onnxPath", "/abs/model.onnx"],
    ["revision", "main"],
    ["repo", "not a repo"],
    ["maxSequenceLength", 0],
    ["inputFormat", "xml"],
  ])("rejects an invalid %s", (field, bad) => {
    const profile = valid();
    profile[field] = bad;
    expect(() => parseModelProfile(profile)).toThrow("Invalid model profile");
  });

  it("rejects an asset path outside the model dir and a missing head output", () => {
    const traversal = valid();
    (traversal.assets as { path: string }[])[0]!.path = "a/../../x";
    expect(() => parseModelProfile(traversal)).toThrow("assets");
    const missingHead = valid();
    delete (missingHead.logitOutputs as Record<string, string>).routing;
    expect(() => parseModelProfile(missingHead)).toThrow("logitOutputs.routing");
  });

  it.each([
    [{}],
    [{ default: { minBenignThreat: 0.75, maxInjection: 1.5, maxToolTag: 0.5 } }],
    [{ default: { minBenignThreat: 0.75, maxInjection: 0.25, maxToolTag: 0.5 }, shell: { minBenignThreat: 0.5, maxInjection: 0.25, maxToolTag: 0.5 } }],
  ])("rejects invalid thresholds %#", (thresholds) => {
    const profile = valid();
    profile.thresholds = thresholds;
    expect(() => parseModelProfile(profile)).toThrow("Invalid model profile: thresholds");
  });

  it("requires the onnx file to be a verified asset", () => {
    const profile = valid();
    profile.onnxPath = "onnx/other/model.onnx";
    expect(() => parseModelProfile(profile)).toThrow("onnxPath not in assets");
  });
});
