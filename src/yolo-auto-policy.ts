import type { PermissionState } from "./types";
import { YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema.ts";

/** Per-head label probabilities from the Lion Warden classifier. */
export type YoloAutoHeads = Record<keyof typeof YOLO_AUTO_LABEL_SCHEMA, Record<string, number>>;

export interface YoloAutoPolicyInput {
  enabled: boolean;
  permissionState: PermissionState;
  source: string;
  eligible: boolean;
  forcedPrompt: boolean;
  workspaceLocal: boolean;
  hardRuleHit: boolean;
  sandboxed: boolean;
  operation: string;
  toolName: string;
  heads: YoloAutoHeads | undefined;
}

export interface YoloAutoPolicyDecision {
  action: "allow" | "prompt";
  reason: string;
}

// ponytail: fixed uncalibrated thresholds; tune from calibration log.
export const YOLO_AUTO_POLICY_THRESHOLDS = {
  minBenignThreat: 0.75,
  maxInjection: 0.25,
  maxToolTag: 0.5,
} as const;
const RESTRICTED_TOOL_CLASSES = new Set(["secrets", "infra", "system"]);
const EXPECTED_TOOL_ACTION: Record<string, string> = {
  read: "read",
  list: "list",
  write: "write",
  edit: "write",
  exec: "exec",
};

/** The tool_action label the model must predict for an operation, if the operation is supported. */
export function expectedToolAction(operation: string): string | undefined {
  return EXPECTED_TOOL_ACTION[operation];
}

function prompt(reason: string): YoloAutoPolicyDecision {
  return { action: "prompt", reason };
}

const PROBABILITY_SUM_TOLERANCE = 1e-3;

function isProbabilityVector(value: unknown): value is Record<string, number> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const entries = Object.entries(value);
  return entries.length > 0 && entries.every(([, score]) =>
    typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 1,
  );
}

function isNormalizedProbabilityVector(value: unknown): value is Record<string, number> {
  if (!isProbabilityVector(value)) return false;
  const total = Object.values(value).reduce((sum, score) => sum + score, 0);
  return Math.abs(total - 1) <= PROBABILITY_SUM_TOLERANCE;
}

function argmax(probs: Record<string, number>): string | undefined {
  let best: string | undefined;
  let highest = -Infinity;
  let tied = false;
  for (const [label, score] of Object.entries(probs)) {
    if (!Number.isFinite(score)) return undefined;
    if (score > highest) {
      best = label;
      highest = score;
      tied = false;
    } else if (score === highest) {
      tied = true;
    }
  }
  return tied ? undefined : best;
}

function isValidModelOutput(value: unknown): value is YoloAutoHeads {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const heads = value as Record<string, unknown>;
  const expectedHeads = Object.keys(YOLO_AUTO_LABEL_SCHEMA) as (keyof YoloAutoHeads)[];
  if (Object.keys(heads).length !== expectedHeads.length
    || expectedHeads.some((head) => !Object.prototype.hasOwnProperty.call(heads, head))) {
    return false;
  }
  return expectedHeads.every((head) => {
    const labels = YOLO_AUTO_LABEL_SCHEMA[head];
    const scores = heads[head];
    if (!isProbabilityVector(scores)) return false;
    if (Object.keys(scores).length !== labels.length
      || !labels.every((label) => Object.prototype.hasOwnProperty.call(scores, label))) {
      return false;
    }
    return head === "tool_tags" || isNormalizedProbabilityVector(scores);
  });
}

export function decideYoloAuto(input: YoloAutoPolicyInput): YoloAutoPolicyDecision {
  if (!input.enabled) return prompt("disabled");
  if (input.permissionState !== "ask") return prompt("permission_state_not_ask");
  if (input.source !== "tool_call") return prompt("source_not_tool_call");
  if (!input.eligible) return prompt("request_not_eligible");
  if (input.forcedPrompt) return prompt("forced_prompt");
  if (!input.workspaceLocal) return prompt("path_not_workspace_local");
  if (input.hardRuleHit) return prompt("sensitive_path");
  const expectedAction = EXPECTED_TOOL_ACTION[input.operation];
  if (!expectedAction) return prompt("unsupported_operation");
  if (expectedAction === "exec" && input.toolName !== "bash") return prompt("exec_not_bash");
  const heads = input.heads;
  if (!heads || typeof heads !== "object") return prompt("model_unavailable");
  if (!isValidModelOutput(heads)) return prompt("invalid_model_output");
  if (argmax(heads.threat) !== "benign") return prompt("threat_not_benign");
  if (!(heads.threat.benign >= YOLO_AUTO_POLICY_THRESHOLDS.minBenignThreat)) return prompt("threat_benign_low_confidence");
  if (!(heads.injection.injection < YOLO_AUTO_POLICY_THRESHOLDS.maxInjection)) return prompt("injection_detected");
  if (!(heads.tool_tags["source:sensitive"] < YOLO_AUTO_POLICY_THRESHOLDS.maxToolTag)) return prompt("source_sensitive");
  if (!(heads.tool_tags["sink:external"] < YOLO_AUTO_POLICY_THRESHOLDS.maxToolTag)) return prompt("sink_external");
  if (argmax(heads.tool_action) !== expectedAction) return prompt("tool_action_mismatch");
  const toolClass = argmax(heads.tool_class);
  if (!toolClass || RESTRICTED_TOOL_CLASSES.has(toolClass)) return prompt("tool_class_restricted");
  return { action: "allow", reason: "model_allow" };
}
