import { describe, expect, it } from "vitest";

import { fuseWithNeighbours } from "./yolo-auto-fusion";
import { YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema";
import type { NeighbourSummary } from "./yolo-auto-neighbours";
import type { YoloAutoHeads } from "./yolo-auto-policy";

function oneHot(labels: readonly string[], winner: string): Record<string, number> {
  const rest = 0.01 / (labels.length - 1);
  return Object.fromEntries(labels.map((l) => [l, l === winner ? 0.99 : rest]));
}

function heads(overrides: { threat?: string; injection?: number; toolClass?: string; tags?: Record<string, number> } = {}): YoloAutoHeads {
  return {
    injection: { benign: 1 - (overrides.injection ?? 0.01), injection: overrides.injection ?? 0.01 },
    threat: oneHot(YOLO_AUTO_LABEL_SCHEMA.threat, overrides.threat ?? "tool_abuse"),
    tool_class: oneHot(YOLO_AUTO_LABEL_SCHEMA.tool_class, overrides.toolClass ?? "shell"),
    tool_action: oneHot(YOLO_AUTO_LABEL_SCHEMA.tool_action, "exec"),
    tool_tags: overrides.tags ?? { "source:sensitive": 0.1, "source:untrusted": 0.5, "sink:external": 0.1 },
    sensitive_document: oneHot(YOLO_AUTO_LABEL_SCHEMA.sensitive_document, "source_code"),
    routing: oneHot(YOLO_AUTO_LABEL_SCHEMA.routing, "tool_operation_request"),
  } as YoloAutoHeads;
}

const none: NeighbourSummary = { workspace: { approvals: 0, denials: 0 }, global: { approvals: 0, denials: 0, workspaces: 0 } };
const ws = (approvals: number, denials = 0): NeighbourSummary => ({ ...none, workspace: { approvals, denials } });
const gl = (approvals: number, workspaces: number, denials = 0): NeighbourSummary => ({ ...none, global: { approvals, denials, workspaces } });
const prompt = { action: "prompt" as const, reason: "threat_not_benign" };
const allow = { action: "allow" as const, reason: "model_allow" };

describe("fuseWithNeighbours", () => {
  it("forces a prompt when any similar past decision was denied, even if the model allowed", () => {
    expect(fuseWithNeighbours(allow, { heads: heads({ threat: "benign" }), hardRuleHit: false, summary: ws(5, 1) }))
      .toEqual({ action: "prompt", reason: "neighbour_denied" });
    expect(fuseWithNeighbours(allow, { heads: heads({ threat: "benign" }), hardRuleHit: false, summary: gl(0, 1, 1) }))
      .toEqual({ action: "prompt", reason: "neighbour_denied" });
  });

  it("allows after 3 workspace approvals with no denials", () => {
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: ws(3) }))
      .toEqual({ action: "allow", reason: "neighbour_workspace_approved" });
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: ws(2) })).toEqual(prompt);
  });

  it("allows from global approvals only across at least two workspaces", () => {
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: gl(3, 2) }))
      .toEqual({ action: "allow", reason: "neighbour_global_approved" });
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: gl(5, 1) })).toEqual(prompt);
  });

  it.each([
    ["hard rule", { hardRuleHit: true }],
    ["injection signal", { heads: heads({ injection: 0.2 }) }],
    ["exfiltration threat", { heads: heads({ threat: "exfiltration_attempt" }) }],
    ["secrets access threat", { heads: heads({ threat: "secrets_access" }) }],
    ["instruction override", { heads: heads({ threat: "instruction_override" }) }],
    ["restricted tool class", { heads: heads({ toolClass: "secrets" }) }],
    ["external sink", { heads: heads({ tags: { "source:sensitive": 0.1, "source:untrusted": 0.5, "sink:external": 0.6 } }) }],
  ])("never lets approvals override a %s", (_name, override) => {
    const input = { heads: heads(), hardRuleHit: false, summary: ws(10), ...override };
    expect(fuseWithNeighbours(prompt, input)).toEqual(prompt);
  });

  it("lets a confident two-class scorer allow when no neighbour rule applies", () => {
    const scorer = { probability: 0.98, samples: 20, positives: 15, negatives: 5 };
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: none, scorer }))
      .toEqual({ action: "allow", reason: "scorer_approved" });
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: none, scorer: { ...scorer, probability: 0.9 } }))
      .toEqual(prompt);
    expect(fuseWithNeighbours(prompt, { heads: heads({ threat: "exfiltration_attempt" }), hardRuleHit: false, summary: none, scorer }))
      .toEqual(prompt);
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: ws(0, 1), scorer }))
      .toEqual({ action: "prompt", reason: "neighbour_denied" });
  });

  it("keeps the model decision when there is no history", () => {
    expect(fuseWithNeighbours(allow, { heads: heads({ threat: "benign" }), hardRuleHit: false, summary: none })).toEqual(allow);
    expect(fuseWithNeighbours(prompt, { heads: heads(), hardRuleHit: false, summary: none })).toEqual(prompt);
  });
});
