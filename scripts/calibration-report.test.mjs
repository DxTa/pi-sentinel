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
});
