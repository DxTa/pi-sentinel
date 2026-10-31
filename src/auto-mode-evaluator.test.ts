import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { AutoModeEvaluator } from "./auto-mode-evaluator";
import type { NeighbourSummary } from "./auto-mode-neighbours";
import type { AutoModeHeads } from "./auto-mode-policy";
import { AUTO_MODE_LABEL_SCHEMA } from "./auto-mode-label-schema";
import { MODEL_REVISION } from "./auto-mode-build";

const request = {
  flow: "permission" as const,
  candidate: true,
  enabled: true,
  permissionState: "ask" as const,
  source: "tool_call",
  eligible: true,
  forcedPrompt: false,
  workspaceLocal: true,
  operation: "read" as const,
  toolName: "read",
  workspaceRelativePath: "src/index.ts",
  hardRuleHit: false,
  sandboxed: false,
  toolCallIdPresent: true,
};

function oneHot(labels: readonly string[], winner: string): Record<string, number> {
  const rest = 0.01 / (labels.length - 1);
  return Object.fromEntries(labels.map((label) => [label, label === winner ? 0.99 : rest]));
}

const heads: AutoModeHeads = {
  injection: oneHot(AUTO_MODE_LABEL_SCHEMA.injection, "benign"),
  threat: oneHot(AUTO_MODE_LABEL_SCHEMA.threat, "benign"),
  tool_class: oneHot(AUTO_MODE_LABEL_SCHEMA.tool_class, "file"),
  tool_action: oneHot(AUTO_MODE_LABEL_SCHEMA.tool_action, "read"),
  tool_tags: { "source:sensitive": 0.1, "source:untrusted": 0.9, "sink:external": 0.1 },
  sensitive_document: oneHot(AUTO_MODE_LABEL_SCHEMA.sensitive_document, "source_code"),
  routing: oneHot(AUTO_MODE_LABEL_SCHEMA.routing, "tool_operation_request"),
}

const lowConfidenceHeads = {
  ...heads,
  threat: Object.fromEntries(
    Object.keys(heads.threat).map((k) => [k, k === "benign" ? 0.6 : 0.4 / 6]),
  ),
};
const neighbours = (
  workspace: Partial<NeighbourSummary["workspace"]> = {},
  global: Partial<NeighbourSummary["global"]> = {},
): NeighbourSummary => ({
  workspace: { approvals: 0, approvalWeight: 0, approvalDays: 0, denials: 0, latestIsDeny: false, ...workspace },
  global: { approvals: 0, approvalWeight: 0, approvalDays: 0, workspaces: 0, denials: 0, denialWorkspaces: 0, ...global },
});

const safeResult = {
  status: "complete" as const,
  evaluationId: "opaque-eval-1",
  buildId: "pi-sentinel-test:model-r1",
  totalLatencyMs: 5,
  heads,
};

describe("AutoModeEvaluator", () => {
  it("evaluates returned heads and emits privacy-safe telemetry once", async () => {
    const evaluate = vi.fn(async () => safeResult);
    const writeReviewLog = vi.fn();
    const writeCalibrationLog = vi.fn();
    let randomCalls = 0;
    const evaluator = new AutoModeEvaluator({
      client: { evaluate },
      waitForStartup: async () => undefined,
      writeReviewLog,
      writeCalibrationLog,
      random: () => { randomCalls += 1; return 0.05; },
    });

    await expect(evaluator.evaluate({ ...request, patternKey: "bash:git status *" })).resolves.toMatchObject({
      action: "allow",
      reason: "model_allow",
      candidate: true,
      evaluationId: "opaque-eval-1",
    });
    expect(evaluate).toHaveBeenCalledWith("tool=read path=src/index.ts");
    expect(writeReviewLog).toHaveBeenCalledOnce();
    expect(writeReviewLog.mock.calls[0]?.[1]).not.toHaveProperty("patternKeyHash");
    expect(writeReviewLog).toHaveBeenCalledWith(
      "auto_mode.evaluation",
      expect.objectContaining({
        evaluationId: "opaque-eval-1",
        flow: "permission",
        candidate: true,
        eligible: true,
        policyThresholds: {
          minBenignThreat: 0.75,
          maxInjection: 0.25,
          maxToolTag: 0.5,
        },
        disposition: "attempted",
        outcome: "allowed",
        policyAction: "allow",
        policyReason: "model_allow",
        modelBuildId: safeResult.buildId,
        classificationLatencyMs: 5,
        totalLatencyMs: expect.any(Number),
      }),
    );
    expect(JSON.stringify(writeReviewLog.mock.calls[0])).not.toContain("src/index.ts");
    expect(JSON.stringify(writeReviewLog.mock.calls[0])).not.toContain("git status");
    expect(randomCalls).toBe(1);
    expect(writeCalibrationLog).toHaveBeenCalledOnce();
    const modelText = "tool=read path=src/index.ts";
    const record = writeCalibrationLog.mock.calls[0]?.[0];
    expect(record).toMatchObject({
      evaluationId: "opaque-eval-1",
      ts: expect.any(String),
      modelRev: MODEL_REVISION,
      toolName: "read",
      operation: "read",
      textLength: modelText.length,
      textSha256: createHash("sha256").update(modelText).digest("hex"),
      truncated: false,
      heads,
      decision: "allow",
      reason: "model_allow",
      hardRuleHit: false,
      audit: false,
      latencyMs: expect.any(Number),
    });
    expect(JSON.stringify(record)).not.toContain("src/index.ts");
  });

  it("records toolCallId on evaluation telemetry for decision joins", async () => {
    const writeReviewLog = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => safeResult) },
      writeReviewLog,
    });

    await evaluator.evaluate({ ...request, toolCallId: "tc-join-1" });

    expect(writeReviewLog).toHaveBeenCalledWith(
      "auto_mode.evaluation",
      expect.objectContaining({ toolCallId: "tc-join-1" }),
    );
  });

  it("records evaluations for the decision store only when scope and key are known", async () => {
    const recordEvaluation = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => safeResult) },
      recordEvaluation,
      random: () => 0.99,
    });

    const decision = await evaluator.evaluate({ ...request, scope: "ws:abc", patternKey: "read:src/*.ts" });
    await evaluator.evaluate(request);

    expect(recordEvaluation).toHaveBeenCalledOnce();
    expect(recordEvaluation).toHaveBeenCalledWith(expect.objectContaining({
      evaluationId: decision.evaluationId,
      scope: "ws:abc",
      patternKey: "read:src/*.ts",
      toolName: "read",
      operation: "read",
      heads: safeResult.heads,
      hardRuleHit: false,
      modelAction: decision.action,
    }));
  });

  it("fuses past decisions: denials force a prompt, approvals can allow a low-confidence model prompt", async () => {
    const summarize = vi.fn();
    const writeReviewLog = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => ({ ...safeResult, heads: lowConfidenceHeads })) },
      summarizeNeighbours: summarize,
      writeReviewLog,
      random: () => 0.99,
    });
    const scoped = { ...request, scope: "ws:abc", patternKey: "read:src/*.ts" };

    summarize.mockReturnValueOnce(neighbours({ approvals: 3, approvalWeight: 2.8, approvalDays: 2 }));
    await expect(evaluator.evaluate(scoped)).resolves.toMatchObject({ action: "allow", reason: "neighbour_workspace_approved" });
    expect(summarize).toHaveBeenCalledWith(expect.objectContaining({
      scope: "ws:abc", toolName: "read", operation: "read", patternKey: "read:src/*.ts", now: expect.any(Number),
    }));
    expect(writeReviewLog).toHaveBeenLastCalledWith("auto_mode.evaluation", expect.objectContaining({
      policyReason: "neighbour_workspace_approved",
      modelPolicyReason: "threat_benign_low_confidence",
      fusionVersion: 2,
      neighbourWorkspaceApprovals: 3,
      neighbourWorkspaceApprovalWeight: 2.8,
      neighbourWorkspaceApprovalDays: 2,
      neighbourWorkspaceLatestDeny: false,
      neighbourDenials: 0,
      neighbourDenialWorkspaces: 0,
    }));

    const benign = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => safeResult) },
      summarizeNeighbours: () => neighbours({ denials: 1, latestIsDeny: true }),
      random: () => 0.99,
    });
    await expect(benign.evaluate(scoped)).resolves.toMatchObject({ action: "prompt", reason: "neighbour_denied" });
  });

  it("does not let approvals override a specific model finding", async () => {
    const riskyHeads = { ...heads, threat: Object.fromEntries(
      Object.keys(heads.threat).map((k) => [k, k === "tool_abuse" ? 0.9 : 0.1 / 6]),
    ) };
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => ({ ...safeResult, heads: riskyHeads })) },
      summarizeNeighbours: () => neighbours({ approvals: 9, approvalWeight: 9, approvalDays: 5 }),
      random: () => 0.99,
    });
    await expect(evaluator.evaluate({ ...request, scope: "ws:abc", patternKey: "read:src/*.ts" }))
      .resolves.toMatchObject({ action: "prompt", reason: "threat_not_benign" });
  });

  it("passes a workspace scorer result into fusion and telemetry", async () => {
    const scoreRequest = vi.fn(() => ({ probability: 0.99, samples: 24, positives: 20, negatives: 4 }));
    const writeReviewLog = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => ({ ...safeResult, heads: lowConfidenceHeads })) },
      summarizeNeighbours: () => neighbours(),
      scoreRequest,
      writeReviewLog,
      random: () => 0.99,
    });

    await expect(evaluator.evaluate({ ...request, scope: "ws:abc", patternKey: "read:src/*.ts" }))
      .resolves.toMatchObject({ action: "allow", reason: "scorer_approved" });
    expect(scoreRequest).toHaveBeenCalledWith(expect.objectContaining({ scope: "ws:abc", features: expect.any(Array) }));
    expect(writeReviewLog).toHaveBeenLastCalledWith("auto_mode.evaluation", expect.objectContaining({
      scorerProbability: 0.99,
      scorerSamples: 24,
    }));
  });

  it("does not store hard-rule evaluations for learning", async () => {
    const recordEvaluation = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => safeResult) },
      recordEvaluation,
      random: () => 0.99,
    });
    await evaluator.evaluate({ ...request, hardRuleHit: true, scope: "ws:abc", patternKey: "ls:etc/*" });
    expect(recordEvaluation).not.toHaveBeenCalled();
  });

  it("stores the pre-fusion model action so fused allows never self-label", async () => {
    const recordEvaluation = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => safeResult) },
      summarizeNeighbours: () => neighbours({ denials: 1, latestIsDeny: true }),
      recordEvaluation,
      random: () => 0.99,
    });
    await evaluator.evaluate({ ...request, scope: "ws:abc", patternKey: "read:src/*.ts" });
    expect(recordEvaluation).toHaveBeenCalledWith(expect.objectContaining({ modelAction: "allow" }));
  });

  it("uses caller-provided text and records truncation metadata", async () => {
    const evaluate = vi.fn(async () => safeResult);
    const writeCalibrationLog = vi.fn();
    const text = "tool=write path=notes.txt content=preview";
    const evaluator = new AutoModeEvaluator({ client: { evaluate }, writeCalibrationLog });

    await evaluator.evaluate({
      ...request,
      operation: "write" as const,
      toolName: "write",
      workspaceRelativePath: "notes.txt",
      text,
      truncated: true,
    });

    expect(evaluate).toHaveBeenCalledWith(text);
    expect(writeCalibrationLog.mock.calls[0]?.[0]).toMatchObject({
      textLength: text.length,
      textSha256: createHash("sha256").update(text).digest("hex"),
      truncated: true,
    });
  });

  it("returns the policy decision without waiting for calibration logging", async () => {
    const writeCalibrationLog = vi.fn(() => new Promise<void>(() => {}));
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: async () => safeResult },
      writeCalibrationLog,
    });

    const outcome = await Promise.race([
      evaluator.evaluate(request).then(() => "returned" as const),
      new Promise<"blocked">((resolve) => setImmediate(() => resolve("blocked"))),
    ]);

    expect(outcome).toBe("returned");
    expect(writeCalibrationLog).toHaveBeenCalledOnce();
  });

  it("turns five percent of would-allow results into audit prompts", async () => {
    const writeCalibrationLog = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: async () => safeResult },
      writeCalibrationLog,
      random: () => 0.049,
    });

    await expect(evaluator.evaluate(request)).resolves.toMatchObject({
      action: "prompt",
      reason: "audit_sample",
      audit: true,
      evaluationId: "opaque-eval-1",
    });
    expect(writeCalibrationLog.mock.calls[0]?.[0]).toMatchObject({
      decision: "prompt",
      reason: "audit_sample",
      audit: true,
    });
  });

  it("audits history-driven allows at twenty percent and flags the stored row", async () => {
    const recordEvaluation = vi.fn();
    const make = (random: number) => new AutoModeEvaluator({
      client: { evaluate: vi.fn(async () => ({ ...safeResult, heads: lowConfidenceHeads })) },
      summarizeNeighbours: () => neighbours({ approvals: 3, approvalWeight: 3, approvalDays: 2 }),
      recordEvaluation,
      random: () => random,
    });
    const scoped = { ...request, scope: "ws:abc", patternKey: "read:src/*.ts" };

    await expect(make(0.19).evaluate(scoped)).resolves.toMatchObject({ action: "prompt", reason: "audit_sample", audit: true });
    expect(recordEvaluation).toHaveBeenLastCalledWith(expect.objectContaining({ audit: true, modelAction: "prompt" }));

    await expect(make(0.21).evaluate(scoped)).resolves.toMatchObject({ action: "allow", reason: "neighbour_workspace_approved", audit: false });
    expect(recordEvaluation).toHaveBeenLastCalledWith(expect.objectContaining({ audit: false }));
  });

  it("keeps the five percent audit rate for plain model allows", async () => {
    const evaluator = new AutoModeEvaluator({
      client: { evaluate: async () => safeResult },
      random: () => 0.19,
    });
    await expect(evaluator.evaluate(request)).resolves.toMatchObject({ action: "allow", audit: false });
  });

  it("prompts when the caller marks a protected path", async () => {
    const evaluator = new AutoModeEvaluator({ client: { evaluate: vi.fn(async () => safeResult) } });

    await expect(evaluator.evaluate({ ...request, hardRuleHit: true })).resolves.toMatchObject({
      action: "prompt",
      reason: "sensitive_path",
      evaluationId: "opaque-eval-1",
    });
  });

  it("fails closed and records one startup failure", async () => {
    const evaluate = vi.fn();
    const writeReviewLog = vi.fn();
    const evaluator = new AutoModeEvaluator({
      client: { evaluate },
      waitForStartup: async () => { throw new Error("worker unavailable"); },
      writeReviewLog,
    });

    await expect(evaluator.evaluate(request)).resolves.toMatchObject({
      action: "prompt",
      reason: "startup_failed",
      candidate: true,
    });
    expect(evaluate).not.toHaveBeenCalled();
    expect(writeReviewLog).toHaveBeenCalledOnce();
    expect(writeReviewLog.mock.calls[0][1]).toMatchObject({
      disposition: "attempted",
      outcome: "prompt",
      failureReason: "startup_failed",
    });
  });

  it("records candidate skips without contacting worker", async () => {
    const evaluate = vi.fn();
    const writeReviewLog = vi.fn();
    const writeCalibrationLog = vi.fn();
    const evaluator = new AutoModeEvaluator({ client: { evaluate }, writeReviewLog, writeCalibrationLog });

    await expect(evaluator.evaluate({ ...request, candidate: false, skipReason: "result_scanning_disabled" })).resolves.toEqual({
      action: "prompt",
      reason: "result_scanning_disabled",
      candidate: false,
      attempted: false,
      evaluationId: expect.any(String),
      audit: false,
    });
    expect(evaluate).not.toHaveBeenCalled();
    expect(writeCalibrationLog.mock.calls[0]?.[0]).toMatchObject({
      heads: null, decision: "prompt", reason: "result_scanning_disabled", audit: false,
    });
    expect(writeReviewLog).toHaveBeenCalledWith(
      "auto_mode.evaluation",
      expect.objectContaining({
        disposition: "skipped",
        outcome: "skipped",
        failureReason: "result_scanning_disabled",
      }),
    );
  });

  describe("Bash inner commands", () => {
    const shellHeads = (benign: number): AutoModeHeads => ({
      ...heads,
      threat: Object.fromEntries(Object.keys(heads.threat).map((k) => [k, k === "benign" ? benign : (1 - benign) / 6])),
      tool_action: oneHot(AUTO_MODE_LABEL_SCHEMA.tool_action, "exec"),
      tool_class: oneHot(AUTO_MODE_LABEL_SCHEMA.tool_class, "shell"),
    });
    const { workspaceRelativePath: _path, ...base } = request;
    // The whole text is what a 256-token window would keep: its tail is cut off.
    const execRequest = {
      ...base,
      operation: "exec" as const,
      toolName: "bash",
      text: "tool=bash command=cd src && echo hi",
      units: ["cd src", "rm -rf build"],
      opaque: false,
    };
    const classify = (benignFor: (text: string) => number) =>
      vi.fn(async (text: string) => ({ ...safeResult, evaluationId: `eval-${text.length}`, heads: shellHeads(benignFor(text)) }));
    const rmIsRisky = (text: string) => (text.includes("rm -rf") ? 0.1 : 0.99);

    it("classifies the whole command and every inner command; one risky unit prompts", async () => {
      const evaluate = classify(rmIsRisky);
      const writeReviewLog = vi.fn();
      const evaluator = new AutoModeEvaluator({ client: { evaluate }, writeReviewLog, random: () => 0.99 });

      await expect(evaluator.evaluate(execRequest)).resolves.toMatchObject({ action: "prompt", reason: "threat_not_benign" });
      expect(evaluate.mock.calls.map(([text]) => text)).toEqual([
        "tool=bash command=cd src && echo hi",
        "tool=bash command=cd src",
        "tool=bash command=rm -rf build",
      ]);
      expect(writeReviewLog).toHaveBeenLastCalledWith("auto_mode.evaluation", expect.objectContaining({
        unitCount: 3, decidingUnit: 2, opaque: false,
      }));
    });

    it("allows only when every unit allows, and stores the least benign unit", async () => {
      const recordEvaluation = vi.fn();
      const evaluate = classify((text) => (text.endsWith("cd src") ? 0.95 : 0.99));
      const evaluator = new AutoModeEvaluator({ client: { evaluate }, recordEvaluation, random: () => 0.99 });

      await expect(evaluator.evaluate({ ...execRequest, scope: "ws:abc", patternKey: "bash:cd *|rm *" }))
        .resolves.toMatchObject({ action: "allow", reason: "model_allow" });
      expect(recordEvaluation).toHaveBeenCalledOnce();
      expect(recordEvaluation).toHaveBeenCalledWith(expect.objectContaining({ heads: shellHeads(0.95), modelAction: "allow" }));
    });

    it("uses a single call for a plain command", async () => {
      const evaluate = classify(() => 0.99);
      const evaluator = new AutoModeEvaluator({ client: { evaluate }, random: () => 0.99 });

      await evaluator.evaluate({ ...execRequest, text: "tool=bash command=ls -la", units: ["ls -la"] });
      expect(evaluate).toHaveBeenCalledOnce();
    });

    it.each([
      ["too_many_units", Array.from({ length: 9 }, (_, i) => `echo ${i}`)],
      ["unit_too_long", ["echo " + "x".repeat(200)]],
      ["unit_too_long", ["echo " + "é".repeat(100)]],
    ])("prompts with %s without contacting the worker", async (reason, units) => {
      const evaluate = classify(() => 0.99);
      const evaluator = new AutoModeEvaluator({ client: { evaluate }, random: () => 0.99 });

      await expect(evaluator.evaluate({ ...execRequest, units })).resolves.toMatchObject({ action: "prompt", reason, attempted: false });
      expect(evaluate).not.toHaveBeenCalled();
    });

    it("prompts instead of throwing when several inputs return malformed heads", async () => {
      const evaluate = vi.fn(async () => ({ ...safeResult, heads: {} as unknown as AutoModeHeads }));
      const evaluator = new AutoModeEvaluator({ client: { evaluate }, random: () => 0.99 });

      await expect(evaluator.evaluate(execRequest)).resolves.toMatchObject({ action: "prompt", reason: "invalid_model_output" });
    });

    it("fingerprints the input that decided in the calibration record", async () => {
      const writeCalibrationLog = vi.fn();
      const evaluator = new AutoModeEvaluator({ client: { evaluate: classify(rmIsRisky) }, writeCalibrationLog, random: () => 0.99 });

      await evaluator.evaluate(execRequest);
      await vi.waitFor(() => expect(writeCalibrationLog).toHaveBeenCalled());
      const decidingText = "tool=bash command=rm -rf build";
      expect(writeCalibrationLog).toHaveBeenCalledWith(expect.objectContaining({
        textLength: decidingText.length,
        textSha256: createHash("sha256").update(decidingText).digest("hex"),
      }));
    });

    it("lets history convert only a single low-confidence unit, never two blocking units", async () => {
      const strongHistory = () => neighbours({ approvals: 3, approvalWeight: 2.8, approvalDays: 2 });
      const lowIf = (match: (text: string) => boolean) => classify((text) => (match(text) ? 0.6 : 0.99));
      const request1 = { ...execRequest, scope: "ws:abc", patternKey: "bash:cd *|rm *" };

      const one = new AutoModeEvaluator({
        client: { evaluate: lowIf((text) => text.endsWith("rm -rf build")) },
        summarizeNeighbours: strongHistory, random: () => 0.99,
      });
      await expect(one.evaluate(request1)).resolves.toMatchObject({ action: "allow", reason: "neighbour_workspace_approved" });

      const two = new AutoModeEvaluator({
        client: { evaluate: lowIf((text) => !text.endsWith("echo hi")) },
        summarizeNeighbours: strongHistory, random: () => 0.99,
      });
      await expect(two.evaluate(request1)).resolves.toMatchObject({ action: "prompt", reason: "threat_benign_low_confidence" });
    });
  });
});
