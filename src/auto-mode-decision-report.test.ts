import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { DecisionRecord, HumanAction } from "./auto-mode-decision-store";
import { buildDecisionReport, exportDenials, verifyDenialExport } from "./auto-mode-decision-report";

function rec(modelAction: "allow" | "prompt", humanAction: HumanAction | null, overrides: Partial<DecisionRecord> = {}): DecisionRecord {
  return {
    evaluationId: Math.random().toString(36),
    ts: 1_000,
    scope: "ws:aaaa",
    toolName: "bash",
    operation: "exec",
    patternKey: "bash:pytest *",
    features: [0.1, 0.9],
    hardRuleHit: false,
    modelAction,
    humanAction,
    humanTs: humanAction ? 2_000 : null,
    ...overrides,
  };
}

describe("buildDecisionReport", () => {
  it("reports per tool/operation agreement between model and human", () => {
    const report = buildDecisionReport([
      rec("allow", "deny"),
      rec("allow", "allow_once"),
      rec("prompt", "session"),
      rec("prompt", "deny"),
      rec("prompt", null),
      rec("prompt", "global", { toolName: "read", operation: "read" }),
    ]);
    expect(report).toEqual([
      { toolName: "bash", operation: "exec", labelled: 4, unlabelled: 1, modelAllowHumanDeny: 1, modelPromptHumanApprove: 1, falseAllowRate: 0.5, approvalRate: 0.5 },
      { toolName: "read", operation: "read", labelled: 1, unlabelled: 0, modelAllowHumanDeny: 0, modelPromptHumanApprove: 1, falseAllowRate: 0, approvalRate: 1 },
    ]);
  });
});

describe("exportDenials", () => {
  const key = "k".repeat(32);
  it("exports only denials with salted key hashes and an HMAC signature", () => {
    const out = exportDenials([rec("allow", "deny"), rec("prompt", "allow_once")], { salt: "s1", key, now: 5_000 });
    expect(out.entries).toHaveLength(1);
    expect(JSON.stringify(out)).not.toContain("pytest");
    expect(out.entries[0]).toEqual({
      toolName: "bash",
      operation: "exec",
      patternKeyHash: createHmac("sha256", "s1").update("bash:pytest *").digest("hex").slice(0, 32),
      features: [0.1, 0.9],
      decidedAt: 2_000,
    });
    expect(out.exportedAt).toBe(5_000);
    expect(verifyDenialExport(out, key)).toBe(true);
    expect(verifyDenialExport({ ...out, entries: [] }, key)).toBe(false);
    expect(verifyDenialExport(out, "x".repeat(32))).toBe(false);
  });
});
