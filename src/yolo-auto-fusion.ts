/**
 * Fuse the frozen model decision with similar past human decisions (D16).
 * Denials always force a prompt. Approvals may allow only when no risk signal is present.
 */
import type { NeighbourSummary } from "./yolo-auto-neighbours";
import type { YoloAutoHeads } from "./yolo-auto-policy";
import type { ScorerResult } from "./yolo-auto-scorer";

export const MIN_WORKSPACE_APPROVALS = 3;
export const MIN_GLOBAL_APPROVALS = 3;
export const MIN_GLOBAL_WORKSPACES = 2;
export const SCORER_ALLOW_PROBABILITY = 0.97;

const BLOCKING_THREATS = new Set([
  "secrets_access",
  "exfiltration_attempt",
  "instruction_override",
  "harmful_behavior",
  "toxic_or_harmful",
]);
const RESTRICTED_CLASSES = new Set(["secrets", "infra", "system"]);

export interface FusionDecision {
  action: "allow" | "prompt";
  reason: string;
}

export interface FusionInput {
  heads: YoloAutoHeads;
  hardRuleHit: boolean;
  summary: NeighbourSummary;
  /** Present only when two-class history is large enough (see scoreWithHistory). */
  scorer?: ScorerResult;
}

function argmax(probs: Record<string, number>): string {
  let best = "";
  let bestValue = -Infinity;
  for (const [label, value] of Object.entries(probs)) {
    if (value > bestValue) {
      best = label;
      bestValue = value;
    }
  }
  return best;
}

function hasRiskSignal(heads: YoloAutoHeads): boolean {
  const h = heads as Record<string, Record<string, number>>;
  return (h.injection?.injection ?? 1) >= 0.1
    || BLOCKING_THREATS.has(argmax(h.threat ?? {}))
    || RESTRICTED_CLASSES.has(argmax(h.tool_class ?? {}))
    || (h.tool_tags?.["source:sensitive"] ?? 1) >= 0.5
    || (h.tool_tags?.["sink:external"] ?? 1) >= 0.5;
}

export function fuseWithNeighbours(model: FusionDecision, input: FusionInput): FusionDecision {
  const { workspace, global } = input.summary;
  if (workspace.denials > 0 || global.denials > 0) {
    return { action: "prompt", reason: "neighbour_denied" };
  }
  if (model.action === "allow" || input.hardRuleHit || hasRiskSignal(input.heads)) return model;
  if (workspace.approvals >= MIN_WORKSPACE_APPROVALS) {
    return { action: "allow", reason: "neighbour_workspace_approved" };
  }
  if (global.approvals >= MIN_GLOBAL_APPROVALS && global.workspaces >= MIN_GLOBAL_WORKSPACES) {
    return { action: "allow", reason: "neighbour_global_approved" };
  }
  if (input.scorer && input.scorer.probability >= SCORER_ALLOW_PROBABILITY) {
    return { action: "allow", reason: "scorer_approved" };
  }
  return model;
}
