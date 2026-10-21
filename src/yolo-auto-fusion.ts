/**
 * Fuse the frozen model decision with similar past human decisions (D16, rules v2).
 * A scope's latest denial forces a prompt. Approvals may convert only one model
 * reason (low-confidence benign) and only when no risk signal is present.
 */
import type { NeighbourSummary } from "./yolo-auto-neighbours";
import { expectedToolAction, YOLO_AUTO_POLICY_THRESHOLDS, type YoloAutoHeads } from "./yolo-auto-policy";
import type { ScorerResult } from "./yolo-auto-scorer";

export const FUSION_VERSION = 2;
/** Decayed approvals (see APPROVAL_HALF_LIFE_MS) needed in one workspace or across workspaces. */
export const MIN_APPROVAL_WEIGHT = 2.5;
export const MIN_APPROVAL_DAYS = 2;
export const MIN_GLOBAL_WORKSPACES = 3;
/** Other workspaces whose latest decision is a denial before it blocks this workspace. */
export const MIN_DENYING_WORKSPACES = 2;
export const MIN_HISTORY_BENIGN = 0.5;
export const SCORER_ALLOW_PROBABILITY = 0.97;
/** History may only resolve the model's uncertainty, never overrule a specific finding. */
export const CONVERTIBLE_REASON = "threat_benign_low_confidence";

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
  operation: string;
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
  return (h.injection?.injection ?? 1) >= YOLO_AUTO_POLICY_THRESHOLDS.maxInjection
    || BLOCKING_THREATS.has(argmax(h.threat ?? {}))
    || RESTRICTED_CLASSES.has(argmax(h.tool_class ?? {}))
    || (h.tool_tags?.["source:sensitive"] ?? 1) >= YOLO_AUTO_POLICY_THRESHOLDS.maxToolTag
    || (h.tool_tags?.["sink:external"] ?? 1) >= YOLO_AUTO_POLICY_THRESHOLDS.maxToolTag;
}

/** True when history may turn this model prompt into an allow. */
function mayConvert(model: FusionDecision, input: FusionInput): boolean {
  if (model.action !== "prompt" || model.reason !== CONVERTIBLE_REASON || input.hardRuleHit) return false;
  const h = input.heads as Record<string, Record<string, number>>;
  const expected = expectedToolAction(input.operation);
  return !hasRiskSignal(input.heads)
    && (h.threat?.benign ?? 0) >= MIN_HISTORY_BENIGN
    && expected !== undefined
    && argmax(h.tool_action ?? {}) === expected;
}

export function fuseWithNeighbours(model: FusionDecision, input: FusionInput): FusionDecision {
  const { workspace, global } = input.summary;
  if (workspace.latestIsDeny || global.denialWorkspaces >= MIN_DENYING_WORKSPACES) {
    return { action: "prompt", reason: "neighbour_denied" };
  }
  if (!mayConvert(model, input)) return model;
  if (workspace.approvalWeight >= MIN_APPROVAL_WEIGHT && workspace.approvalDays >= MIN_APPROVAL_DAYS) {
    return { action: "allow", reason: "neighbour_workspace_approved" };
  }
  if (global.approvalWeight >= MIN_APPROVAL_WEIGHT
    && global.approvalDays >= MIN_APPROVAL_DAYS
    && global.workspaces >= MIN_GLOBAL_WORKSPACES
    && global.denialWorkspaces === 0) {
    return { action: "allow", reason: "neighbour_global_approved" };
  }
  if (input.scorer && input.scorer.probability >= SCORER_ALLOW_PROBABILITY) {
    return { action: "allow", reason: "scorer_approved" };
  }
  return model;
}
