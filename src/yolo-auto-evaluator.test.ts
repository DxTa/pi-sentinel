import { describe, expect, it, vi } from "vitest";

import { YoloAutoEvaluator } from "./yolo-auto-evaluator";

const request = {
  flow: "permission" as const,
  candidate: true,
  enabled: true,
  maxLevel: "l2" as const,
  permissionState: "ask" as const,
  source: "tool_call",
  eligible: true,
  forcedPrompt: false,
  workspaceLocal: true,
  operation: "read" as const,
  toolName: "read",
  workspaceRelativePath: "src/index.ts",
  toolCallIdPresent: true,
};

const safeResult = {
  status: "complete" as const,
  evaluationId: "opaque-eval-1",
  phases: [
    { phase: "l1" as const, status: "complete" as const, latencyMs: 2 },
    { phase: "l2" as const, status: "complete" as const, latencyMs: 3 },
  ],
  totalLatencyMs: 5,
  escalated: false,
  l1: { verdict: "safe" as const, accepted: true, complete: true, degraded: false, provenance: "model-l1" },
  l2: {
    escalated: false,
    results: [
      { category: "injection", className: "safe", accepted: true, complete: true, degraded: false },
      { category: "tool_class", className: "file", accepted: true, complete: true, degraded: false, provenance: "model-l2" },
      { category: "tool_action", className: "read", accepted: true, complete: true, degraded: false },
      ...["source_sensitive", "source_untrusted", "sink_external"].map((pipeline) => ({
        category: "tool_tags",
        pipeline,
        className: "absent",
        accepted: true,
        complete: true,
        degraded: false,
      })),
    ],
  },
  l3: undefined,
};

describe("YoloAutoEvaluator", () => {
  it("evaluates policy and emits privacy-safe telemetry once", async () => {
    const evaluate = vi.fn(async () => safeResult);
    const writeReviewLog = vi.fn();
    const evaluator = new YoloAutoEvaluator({
      client: { evaluate },
      waitForStartup: async () => undefined,
      writeReviewLog,
    });

    await expect(evaluator.evaluate(request)).resolves.toMatchObject({
      action: "allow",
      reason: "safe_workspace_read",
      candidate: true,
      evaluationId: "opaque-eval-1",
    });
    expect(evaluate).toHaveBeenCalledWith({
      toolName: "read",
      operation: "read",
      workspaceRelativePath: "src/index.ts",
      metadata: { input_has_path: true, tool_call_id_present: true },
    }, "l2");
    expect(writeReviewLog).toHaveBeenCalledOnce();
    expect(writeReviewLog).toHaveBeenCalledWith(
      "yolo_auto.evaluation",
      expect.objectContaining({
        evaluationId: "opaque-eval-1",
        flow: "permission",
        disposition: "attempted",
        outcome: "allowed",
        policyAction: "allow",
        policyReason: "safe_workspace_read",
        phases: safeResult.phases,
        modelProvenance: { l1: "model-l1", l2: ["model-l2"], l3: null },
        totalLatencyMs: expect.any(Number),
      }),
    );
    expect(JSON.stringify(writeReviewLog.mock.calls[0])).not.toContain("src/index.ts");
  });

  it("mirrors evaluation telemetry into the debug stream", async () => {
    const writeDebugLog = vi.fn();
    const evaluator = new YoloAutoEvaluator({
      client: { evaluate: vi.fn(async () => safeResult) },
      writeDebugLog,
    } as never);

    await evaluator.evaluate(request);

    expect(writeDebugLog).toHaveBeenCalledWith(
      "yolo_auto.evaluation",
      expect.objectContaining({
        evaluationId: "opaque-eval-1",
        phases: safeResult.phases,
        totalLatencyMs: expect.any(Number),
      }),
    );
    expect(JSON.stringify(writeDebugLog.mock.calls[0])).not.toContain("src/index.ts");
  });

  it("fails closed and records one startup failure", async () => {
    const evaluate = vi.fn();
    const writeReviewLog = vi.fn();
    const evaluator = new YoloAutoEvaluator({
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
    const evaluator = new YoloAutoEvaluator({
      client: { evaluate },
      writeReviewLog,
    });

    await expect(evaluator.evaluate({ ...request, candidate: false, skipReason: "result_scanning_disabled" })).resolves.toEqual({
      action: "prompt",
      reason: "result_scanning_disabled",
      candidate: false,
      attempted: false,
      evaluationId: expect.any(String),
    });
    expect(evaluate).not.toHaveBeenCalled();
    expect(writeReviewLog).toHaveBeenCalledWith(
      "yolo_auto.evaluation",
      expect.objectContaining({
        disposition: "skipped",
        outcome: "skipped",
        failureReason: "result_scanning_disabled",
      }),
    );
  });
});
