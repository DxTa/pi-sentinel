import { describe, expect, it } from "vitest";

import { fuseWithNeighbours } from "./yolo-auto-fusion";
import { YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema";
import type { NeighbourSummary } from "./yolo-auto-neighbours";
import type { YoloAutoHeads } from "./yolo-auto-policy";

function oneHot(labels: readonly string[], winner: string): Record<string, number> {
  const rest = 0.01 / (labels.length - 1);
  return Object.fromEntries(labels.map((l) => [l, l === winner ? 0.99 : rest]));
}

function heads(
  overrides: { threat?: string; injection?: number; toolClass?: string; action?: string; tags?: Record<string, number> } = {},
): YoloAutoHeads {
  return {
    injection: { benign: 1 - (overrides.injection ?? 0.01), injection: overrides.injection ?? 0.01 },
    threat: oneHot(YOLO_AUTO_LABEL_SCHEMA.threat, overrides.threat ?? "benign"),
    tool_class: oneHot(YOLO_AUTO_LABEL_SCHEMA.tool_class, overrides.toolClass ?? "shell"),
    tool_action: oneHot(YOLO_AUTO_LABEL_SCHEMA.tool_action, overrides.action ?? "exec"),
    tool_tags: overrides.tags ?? { "source:sensitive": 0.1, "source:untrusted": 0.5, "sink:external": 0.1 },
    sensitive_document: oneHot(YOLO_AUTO_LABEL_SCHEMA.sensitive_document, "source_code"),
    routing: oneHot(YOLO_AUTO_LABEL_SCHEMA.routing, "tool_operation_request"),
  } as YoloAutoHeads;
}

const none: NeighbourSummary = {
  workspace: { approvals: 0, approvalWeight: 0, approvalDays: 0, denials: 0, latestIsDeny: false },
  global: { approvals: 0, approvalWeight: 0, approvalDays: 0, workspaces: 0, denials: 0, denialWorkspaces: 0 },
};
/** Project history: `weight` approvals spread over `days` days. */
const ws = (weight: number, days = 2, extra: Partial<NeighbourSummary["workspace"]> = {}): NeighbourSummary => ({
  ...none,
  workspace: { ...none.workspace, approvals: Math.ceil(weight), approvalWeight: weight, approvalDays: days, ...extra },
});
const gl = (weight: number, workspaces: number, days = 2, extra: Partial<NeighbourSummary["global"]> = {}): NeighbourSummary => ({
  ...none,
  global: { ...none.global, approvals: Math.ceil(weight), approvalWeight: weight, approvalDays: days, workspaces, ...extra },
});
const lowConfidence = { action: "prompt" as const, reason: "threat_benign_low_confidence" };
const allow = { action: "allow" as const, reason: "model_allow" };
const base = { heads: heads(), hardRuleHit: false, operation: "exec" };

describe("fuseWithNeighbours: denial", () => {
  it("prompts when this workspace's latest decision is a denial, even if the model allowed", () => {
    expect(fuseWithNeighbours(allow, { ...base, summary: ws(5, 3, { denials: 1, latestIsDeny: true }) }))
      .toEqual({ action: "prompt", reason: "neighbour_denied" });
  });

  it("ignores an older denial that a later approval cleared", () => {
    expect(fuseWithNeighbours(allow, { ...base, summary: ws(1, 1, { denials: 1, latestIsDeny: false }) })).toEqual(allow);
  });

  it("prompts from other workspaces only after denials in at least two of them", () => {
    expect(fuseWithNeighbours(allow, { ...base, summary: gl(0, 0, 0, { denials: 1, denialWorkspaces: 1 }) })).toEqual(allow);
    expect(fuseWithNeighbours(allow, { ...base, summary: gl(0, 0, 0, { denials: 2, denialWorkspaces: 2 }) }))
      .toEqual({ action: "prompt", reason: "neighbour_denied" });
  });
});

describe("fuseWithNeighbours: project allow", () => {
  it("allows a low-confidence benign prompt after enough decayed approvals over two days", () => {
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary: ws(2.5, 2) }))
      .toEqual({ action: "allow", reason: "neighbour_workspace_approved" });
  });

  it.each([
    ["too little weight", ws(2.4, 3)],
    ["a single day", ws(3, 1)],
  ])("keeps the prompt with %s", (_name, summary) => {
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary })).toEqual(lowConfidence);
  });
});

describe("fuseWithNeighbours: global allow", () => {
  it("allows after approvals in three workspaces over two days with no denying workspace", () => {
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary: gl(3, 3, 2) }))
      .toEqual({ action: "allow", reason: "neighbour_global_approved" });
  });

  it.each([
    ["two workspaces", gl(5, 2, 3)],
    ["one day", gl(5, 3, 1)],
    ["low weight", gl(2, 3, 3)],
    ["a denying workspace", gl(5, 3, 3, { denials: 1, denialWorkspaces: 1 })],
  ])("keeps the prompt with %s", (_name, summary) => {
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary })).toEqual(lowConfidence);
  });
});

describe("fuseWithNeighbours: what history may override", () => {
  it.each([
    ["threat_not_benign"], ["injection_detected"], ["tool_action_mismatch"], ["sensitive_path"],
    ["path_not_workspace_local"], ["source_sensitive"],
  ])("never converts the model reason %s", (reason) => {
    const model = { action: "prompt" as const, reason };
    expect(fuseWithNeighbours(model, { ...base, summary: ws(10, 5) })).toEqual(model);
  });

  it.each([
    ["hard rule", { hardRuleHit: true }],
    ["injection signal", { heads: heads({ injection: 0.2 }) }],
    ["restricted tool class", { heads: heads({ toolClass: "secrets" }) }],
    ["sensitive source", { heads: heads({ tags: { "source:sensitive": 0.6, "source:untrusted": 0.5, "sink:external": 0.1 } }) }],
    ["external sink", { heads: heads({ tags: { "source:sensitive": 0.1, "source:untrusted": 0.5, "sink:external": 0.6 } }) }],
    ["tool action that differs from the operation", { heads: heads({ action: "network" }) }],
    ["benign score below the floor", { heads: heads({ threat: "tool_abuse" }) }],
  ])("never lets approvals override a %s", (_name, override) => {
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary: ws(10, 5), ...override })).toEqual(lowConfidence);
  });

  it("never lets a scorer override those checks", () => {
    const scorer = { probability: 0.99, samples: 20, positives: 15, negatives: 5 };
    expect(fuseWithNeighbours(lowConfidence, { ...base, heads: heads({ action: "network" }), summary: none, scorer }))
      .toEqual(lowConfidence);
    expect(fuseWithNeighbours({ action: "prompt", reason: "threat_not_benign" }, { ...base, summary: none, scorer }))
      .toEqual({ action: "prompt", reason: "threat_not_benign" });
  });
});

describe("fuseWithNeighbours: scorer and no history", () => {
  it("lets a confident two-class scorer allow when no neighbour rule applies", () => {
    const scorer = { probability: 0.98, samples: 20, positives: 15, negatives: 5 };
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary: none, scorer }))
      .toEqual({ action: "allow", reason: "scorer_approved" });
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary: none, scorer: { ...scorer, probability: 0.9 } }))
      .toEqual(lowConfidence);
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary: ws(0, 0, { denials: 1, latestIsDeny: true }), scorer }))
      .toEqual({ action: "prompt", reason: "neighbour_denied" });
  });

  it("keeps the model decision when there is no history", () => {
    expect(fuseWithNeighbours(allow, { ...base, summary: none })).toEqual(allow);
    expect(fuseWithNeighbours(lowConfidence, { ...base, summary: none })).toEqual(lowConfidence);
  });
});
