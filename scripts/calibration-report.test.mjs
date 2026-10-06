import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { buildCalibrationReport } from "./calibration-report.mjs";

const threatLabels = ["instruction_override", "secrets_access", "tool_abuse", "harmful_behavior", "exfiltration_attempt", "toxic_or_harmful", "benign"];
const actionLabels = ["read", "write", "list", "exec", "network", "unknown"];
const classLabels = ["file", "database", "vcs", "api", "memory", "messaging", "web", "browser", "shell", "code", "system", "secrets", "infra", "unknown"];

function distribution(labels, selected, confidence) {
  const remainder = (1 - confidence) / (labels.length - 1);
  return Object.fromEntries(labels.map((label) => [label, label === selected ? confidence : remainder]));
}

function calibration(evaluationId, overrides = {}) {
  const benign = overrides.benign ?? 0.95;
  const injection = overrides.injection ?? 0.01;
  const action = overrides.action ?? "read";
  const actionConfidence = overrides.actionConfidence ?? 0.9;
  const toolClass = overrides.toolClass ?? "file";
  const toolClassConfidence = overrides.toolClassConfidence ?? 0.9;
  return {
    evaluationId,
    operation: "read",
    hardRuleHit: overrides.hardRuleHit ?? false,
    heads: {
      threat: Object.fromEntries(threatLabels.map((label) => [
        label,
        label === "benign" ? benign : label === "instruction_override" ? 1 - benign : 0,
      ])),
      injection: { benign: 1 - injection, injection },
      tool_tags: {
        "source:sensitive": overrides.sourceSensitive ?? 0.1,
        "source:untrusted": 0.1,
        "sink:external": overrides.sinkExternal ?? 0.1,
      },
      tool_action: distribution(actionLabels, action, actionConfidence),
      tool_class: distribution(classLabels, toolClass, toolClassConfidence),
      sensitive_document: { other: 1 },
      routing: { tool_operation_request: 1 },
    },
  };
}

const review = (evaluationId, event) => ({ evaluationId, event: "permission_request." + event });

describe("calibration report", () => {
  it("joins human labels and reports precision/recall at policy thresholds", () => {
    const report = buildCalibrationReport(
      [
        calibration("allow-label"),
        calibration("deny-label"),
        calibration("approved-but-gates-fail", {
          benign: 0.4,
          injection: 0.2,
          sourceSensitive: 0.8,
          actionConfidence: 0.9,
          toolClass: "secrets",
          toolClassConfidence: 0.9,
        }),
        calibration("denied-and-gates-fail", {
          benign: 0.4,
          injection: 0.5,
          sourceSensitive: 0.8,
          sinkExternal: 0.8,
          action: "network",
          actionConfidence: 0.9,
          toolClass: "system",
          toolClassConfidence: 0.9,
        }),
        calibration("automatic-allow-has-no-human-label"),
        calibration("hard-rule-excluded", { hardRuleHit: true }),
      ],
      [
        review("allow-label", "approved"),
        review("deny-label", "denied"),
        review("approved-but-gates-fail", "approved"),
        review("denied-and-gates-fail", "denied"),
        review("automatic-allow-has-no-human-label", "yolo_auto_approved"),
        review("hard-rule-excluded", "denied"),
      ],
    );

    expect(report).toMatchObject({ joined: 4, unlabeled: 1, excluded: 1, unmatchedLabels: 0 });
    const row = (head, threshold) => report.rows.find((item) => item.head === head && item.threshold === threshold);
    expect(row("threat.benign", ">=0.90")).toMatchObject({ n: 4, tp: 1, fp: 1, fn: 1, precision: 0.5, recall: 0.5 });
    expect(row("injection.injection", "<0.10")).toMatchObject({ n: 4, tp: 1, fp: 1, fn: 1, precision: 0.5, recall: 0.5 });
    expect(row("tool_tags.sink:external", "<0.50")).toMatchObject({ n: 4, tp: 2, fp: 1, fn: 0, precision: 2 / 3, recall: 1 });
    expect(row("tool_action", "argmax")).toMatchObject({ n: 4, tp: 2, fp: 1, fn: 0, precision: 2 / 3, recall: 1 });
  });

  it("filters by evaluation time and keeps labels recorded after the window", () => {
    const since = Date.parse("2026-10-01T10:00:00Z");
    const until = Date.parse("2026-10-01T12:00:00Z");
    const records = [
      { ...calibration("at-since"), ts: "2026-10-01T10:00:00Z", toolName: "bash", operation: "exec", decision: "allow", reason: "model_allow" },
      { ...calibration("inside"), ts: "2026-10-01T11:00:00Z", toolName: "bash", operation: "exec", decision: "prompt", reason: "audit_sample" },
      { ...calibration("at-until"), ts: "2026-10-01T12:00:00Z", toolName: "bash", operation: "exec", decision: "prompt", reason: "injection_detected" },
      { ...calibration("missing-time"), toolName: "bash", operation: "exec", decision: "prompt", reason: "transport_failure" },
    ];
    const telemetry = (evaluationId) => ({
      event: "yolo_auto.evaluation",
      evaluationId,
      flow: "permission",
      candidate: true,
      eligible: true,
      disposition: "attempted",
      policyThresholds: { minBenignThreat: 0.9, maxInjection: 0.1, maxToolTag: 0.5 },
    });
    const report = buildCalibrationReport(
      records,
      [
        telemetry("at-since"),
        telemetry("inside"),
        telemetry("at-until"),
        review("at-since", "approved"),
        { ...review("inside", "denied"), timestamp: "2026-10-01T14:00:00Z" },
      ],
      { since, until },
    );

    expect(report).toMatchObject({
      totalEvaluations: 2,
      invalidTimestamps: 1,
      joined: 2,
      unlabeled: 0,
      excluded: 0,
      unmatchedLabels: 0,
    });
    expect(report.coverage).toHaveLength(1);
    expect(report.coverage[0]).toMatchObject({
      flow: "permission",
      toolName: "bash",
      operation: "exec",
      evaluations: 2,
      candidates: 2,
      eligible: 2,
      attempted: 2,
      scored: 2,
      allowed: 1,
      prompted: 1,
      labelled: 2,
      humanApproved: 1,
      humanDenied: 1,
    });
  });

  it("keeps coverage separate by model build and threshold snapshot", () => {
    const baseThresholds = { minBenignThreat: 0.9, maxInjection: 0.1, maxToolTag: 0.5 };
    const telemetry = (evaluationId, modelBuildId, policyThresholds) => ({
      event: "yolo_auto.evaluation",
      evaluationId,
      flow: "permission",
      candidate: true,
      eligible: true,
      disposition: "attempted",
      modelBuildId,
      policyThresholds,
    });
    const report = buildCalibrationReport(
      ["build-a", "threshold-b", "build-c"].map((evaluationId) => ({
        ...calibration(evaluationId),
        toolName: "bash",
        operation: "exec",
      })),
      [
        telemetry("build-a", "model-a", baseThresholds),
        telemetry("threshold-b", "model-a", { ...baseThresholds, maxInjection: 0.2 }),
        telemetry("build-c", "model-b", baseThresholds),
      ],
    );

    expect(report.coverage).toHaveLength(3);
    expect(report.coverage.map(({ modelBuildId, policyThresholds }) => [
      modelBuildId,
      policyThresholds.maxInjection,
    ])).toEqual([["model-a", 0.1], ["model-a", 0.2], ["model-b", 0.1]]);
  });

  it("separates routine skips from attempted failures and reports missing disposition metadata", () => {
    const report = buildCalibrationReport(
      [
        {
          ...calibration("failed-read"),
          ts: "2026-10-01T10:00:00Z",
          toolName: "read",
          operation: "read",
          heads: null,
          decision: "prompt",
          reason: "transport_failure",
        },
        {
          ...calibration("routine-skip"),
          ts: "2026-10-01T10:00:00Z",
          toolName: "read",
          operation: "read",
          heads: null,
          decision: "prompt",
          reason: "result_scanning_disabled",
        },
        {
          ...calibration("legacy-read"),
          ts: "2026-10-01T10:00:00Z",
          toolName: "read",
          operation: "read",
          heads: null,
          decision: "prompt",
          reason: "startup_failed",
        },
      ],
      [
        {
          event: "yolo_auto.evaluation",
          evaluationId: "failed-read",
          flow: "secret_read",
          candidate: true,
          eligible: true,
          disposition: "attempted",
          failureReason: "transport_failure",
        },
        {
          event: "yolo_auto.evaluation",
          evaluationId: "routine-skip",
          flow: "secret_read",
          candidate: false,
          eligible: false,
          disposition: "skipped",
          failureReason: "result_scanning_disabled",
        },
        {
          event: "yolo_auto.evaluation",
          evaluationId: "legacy-read",
          flow: "secret_read",
          candidate: true,
          eligible: true,
          failureReason: "startup_failed",
        },
      ],
    );

    expect(report.coverage).toHaveLength(1);
    expect(report.coverage[0]).toMatchObject({
      flow: "secret_read",
      evaluations: 3,
      candidates: 2,
      eligible: 2,
      attempted: 1,
      skipped: 1,
      dispositionMetadataMissing: 1,
      failures: 1,
      missingHeads: 3,
      reasons: { transport_failure: 1, result_scanning_disabled: 1, startup_failed: 1 },
    });
  });
});


describe("session-scoped report", () => {
  it("joins multiple roots and reports decisions separately from private permission inputs", () => {
    const temp = mkdtempSync(join(tmpdir(), "pi-sentinel-report-"));
    const rootA = join(temp, "sessions-a");
    const rootB = join(temp, "sessions-b");
    const calibrationPath = join(temp, "calibration.jsonl");
    const reviewPath = join(temp, "review.jsonl");
    mkdirSync(rootA);
    mkdirSync(rootB);
    writeFileSync(calibrationPath, "");

    const writeJsonl = (path, rows) =>
      writeFileSync(path, rows.map((row) => JSON.stringify(row)).join("\n") + "\n");
    const toolCall = (id, name, args, timestamp = "2026-10-05T10:00:00Z") => ({
      type: "message",
      timestamp,
      message: {
        role: "assistant",
        content: [{ type: "toolCall", id, name, arguments: args }],
      },
    });
    writeJsonl(join(rootA, "session-a.jsonl"), [
      { type: "session", id: "session-a", cwd: "/workspace/a" },
      { type: "message", timestamp: "2026-10-05T09:59:00Z", message: { role: "user", content: [{ type: "text", text: "PRIVATE_PROMPT" }] } },
      toolCall("call-a", "bash", { command: "PRIVATE_COMMAND" }),
    ]);
    writeJsonl(join(rootB, "session-b.jsonl"), [
      { type: "session", id: "session-b", cwd: "/workspace/b" },
      toolCall("call-a", "bash", { command: "PRIVATE_DUPLICATE_COMMAND" }),
      toolCall("call-b", "read", { path: "PRIVATE_PATH" }),
      toolCall("call-c", "bash", { command: "PRIVATE_PENDING_COMMAND" }),
      toolCall("call-d", "bash", { command: "PRIVATE_DENIED_COMMAND" }),
      toolCall("call-since", "read", { path: "PRIVATE_BOUNDARY_PATH" }, "2026-10-05T00:00:00Z"),
      toolCall("call-until", "bash", { command: "PRIVATE_UNTIL_COMMAND" }, "2026-10-06T00:00:00Z"),
    ]);
    writeJsonl(reviewPath, [
      {
        event: "yolo_auto.evaluation", timestamp: "2026-10-05T10:00:01Z",
        evaluationId: "eval-a", toolCallId: "call-a", modelBuildId: "build-a",
        outcome: "prompt", policyAction: "prompt", policyReason: "threat_not_benign", disposition: "attempted",
        toolName: "bash", operation: "exec", command: "PRIVATE_REVIEW_COMMAND",
      },
      {
        event: "permission_request.waiting", timestamp: "2026-10-05T10:00:02Z",
        requestId: "request-a", toolCallId: "call-a", toolName: "bash",
        yoloAutoOperation: "exec", yoloAutoEligible: false, message: "PRIVATE_PROMPT_BODY",
      },
      {
        event: "permission_request.approved", timestamp: "2026-10-05T10:00:03Z",
        requestId: "request-a", toolCallId: "call-a", toolName: "bash",
        yoloAutoOperation: "exec", yoloAutoEligible: false, resolution: "approved",
      },
      {
        event: "yolo_auto.evaluation", timestamp: "2026-10-05T10:00:04Z",
        evaluationId: "eval-b", toolCallId: "call-b", modelBuildId: "build-a",
        outcome: "allowed", policyAction: "allow", policyReason: "model_allow", disposition: "attempted",
        toolName: "read", operation: "read",
      },
      {
        event: "permission_request.waiting", timestamp: "2026-10-05T10:00:05Z",
        requestId: "request-c", toolCallId: "call-c", toolName: "bash",
        yoloAutoOperation: "exec", yoloAutoEligible: false, command: "PRIVATE_PENDING_COMMAND",
      },
      {
        event: "permission_request.waiting", timestamp: "2026-10-05T10:00:05Z",
        requestId: "request-a", toolCallId: "call-d", toolName: "bash",
        yoloAutoOperation: "exec", yoloAutoEligible: false,
      },
      {
        event: "permission_request.denied", timestamp: "2026-10-05T10:00:06Z",
        requestId: "request-a", toolCallId: "call-d", toolName: "bash",
        yoloAutoOperation: "exec", yoloAutoEligible: false, resolution: "denied",
      },
      {
        event: "yolo_auto.evaluation", timestamp: "2026-10-05T00:00:00Z",
        evaluationId: "eval-since", toolCallId: "call-since", modelBuildId: "build-a",
        outcome: "allowed", policyAction: "allow", policyReason: "model_allow", disposition: "attempted",
      },
      {
        event: "yolo_auto.evaluation", timestamp: "2026-10-06T00:00:00Z",
        evaluationId: "eval-until", toolCallId: "call-until", modelBuildId: "build-x",
        outcome: "prompt", policyAction: "prompt", policyReason: "injection_detected",
      },
      {
        event: "yolo_auto.evaluation", timestamp: "2026-10-05T10:00:06Z",
        evaluationId: "unrelated", toolCallId: "not-in-selected-sessions", modelBuildId: "build-x",
        outcome: "allowed", command: "PRIVATE_UNRELATED_COMMAND",
      },
    ]);

    try {
      const script = fileURLToPath(new URL("./calibration-report.mjs", import.meta.url));
      const result = spawnSync(process.execPath, [
        script, calibrationPath, reviewPath,
        "--since", "2026-10-05T00:00:00Z",
        "--until", "2026-10-06T00:00:00Z",
        "--session-root", rootA,
        "--session-root", rootB,
      ], { encoding: "utf8" });

      expect(result.status).toBe(0);
      expect(result.stdout).toContain("Session roots: 2; sessions: 2; tool calls: 5");
      expect(result.stdout).toContain("Approval evaluations: 3");
      expect(result.stdout).toContain("outcomes: allowed=2, prompt=1");
      expect(result.stdout).toContain("Evaluation dispositions: attempted=3");
      expect(result.stdout).toContain("Model attempts by build: build-a=3");
      expect(result.stdout).toContain("Session activity uses the supplied roots; calibration tables above use the selected logs.");
      expect(result.stdout).toContain("Permission requests: waited=3; resolved=2; approved=1; denied=1; other_resolved=0; pending=1");
      expect(result.stdout).toContain("threat_not_benign=1");
      for (const secret of ["PRIVATE_PROMPT", "PRIVATE_COMMAND", "PRIVATE_PATH", "PRIVATE_REVIEW_COMMAND", "PRIVATE_PROMPT_BODY", "PRIVATE_PENDING_COMMAND", "PRIVATE_DUPLICATE_COMMAND", "PRIVATE_DENIED_COMMAND", "PRIVATE_BOUNDARY_PATH", "PRIVATE_UNTIL_COMMAND", "PRIVATE_UNRELATED_COMMAND"]) {
        expect(result.stdout).not.toContain(secret);
      }
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
});
