import type { PermissionState } from "./types";
import { AUTO_MODE_LABEL_SCHEMA } from "./auto-mode-label-schema.ts";
import { MODEL_PROFILE } from "./auto-mode-build.ts";
import type { AutoModeOperation, AutoModeThresholds, AutoModeThresholdSet } from "./auto-mode-profile.ts";

/** Per-head label probabilities from the Lion Warden classifier. */
export type AutoModeHeads = Record<keyof typeof AUTO_MODE_LABEL_SCHEMA, Record<string, number>>;

export interface AutoModePolicyInput {
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
  heads: AutoModeHeads | undefined;
  /** Threshold set to judge with; defaults to the active model profile's. */
  thresholds?: AutoModeThresholdSet;
}

export interface AutoModePolicyDecision {
  action: "allow" | "prompt";
  reason: string;
}

// shortcut: profile defaults are still uncalibrated; scripts/calibrate.ts sets them (plan step 6).
export const AUTO_MODE_POLICY_THRESHOLDS: AutoModeThresholds = MODEL_PROFILE.thresholds.default;

/** Thresholds for one operation: its own entry, else the set's default. */
export function thresholdsFor(operation: string, set: AutoModeThresholdSet = MODEL_PROFILE.thresholds): AutoModeThresholds {
  return set[operation as AutoModeOperation] ?? set.default;
}
const RESTRICTED_TOOL_CLASSES = new Set(["secrets", "infra", "system"]);
/** pi names MCP tools `mcp__<server>__<tool>`. */
export const MCP_TOOL_PREFIX = "mcp__";
const MCP_ALLOWED_ACTIONS = new Set(["read", "list"]);
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

function prompt(reason: string): AutoModePolicyDecision {
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

function isValidModelOutput(value: unknown): value is AutoModeHeads {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const heads = value as Record<string, unknown>;
  const expectedHeads = Object.keys(AUTO_MODE_LABEL_SCHEMA) as (keyof AutoModeHeads)[];
  if (Object.keys(heads).length !== expectedHeads.length
    || expectedHeads.some((head) => !Object.prototype.hasOwnProperty.call(heads, head))) {
    return false;
  }
  return expectedHeads.every((head) => {
    const labels = AUTO_MODE_LABEL_SCHEMA[head];
    const scores = heads[head];
    if (!isProbabilityVector(scores)) return false;
    if (Object.keys(scores).length !== labels.length
      || !labels.every((label) => Object.prototype.hasOwnProperty.call(scores, label))) {
      return false;
    }
    return head === "tool_tags" || isNormalizedProbabilityVector(scores);
  });
}

export function decideAutoMode(input: AutoModePolicyInput): AutoModePolicyDecision {
  if (!input.enabled) return prompt("disabled");
  if (input.permissionState !== "ask") return prompt("permission_state_not_ask");
  if (input.source !== "tool_call") return prompt("source_not_tool_call");
  if (!input.eligible) return prompt("request_not_eligible");
  if (input.forcedPrompt) return prompt("forced_prompt");
  if (!input.workspaceLocal) return prompt("path_not_workspace_local");
  if (input.hardRuleHit) return prompt("sensitive_path");
  const isMcpTool = input.operation === "tool";
  if (isMcpTool && !input.toolName.startsWith(MCP_TOOL_PREFIX)) return prompt("tool_not_mcp");
  const expectedAction = EXPECTED_TOOL_ACTION[input.operation];
  if (!expectedAction && !isMcpTool) return prompt("unsupported_operation");
  if (expectedAction === "exec" && input.toolName !== "bash") return prompt("exec_not_bash");
  const heads = input.heads;
  if (!heads || typeof heads !== "object") return prompt("model_unavailable");
  if (!isValidModelOutput(heads)) return prompt("invalid_model_output");
  if (argmax(heads.threat) !== "benign") return prompt("threat_not_benign");
  const t = thresholdsFor(input.operation, input.thresholds);
  if (!(heads.threat.benign >= t.minBenignThreat)) return prompt("threat_benign_low_confidence");
  if (!(heads.injection.injection < t.maxInjection)) return prompt("injection_detected");
  if (!(heads.tool_tags["source:sensitive"] < t.maxToolTag)) return prompt("source_sensitive");
  if (!(heads.tool_tags["sink:external"] < t.maxToolTag)) return prompt("sink_external");
  const action = argmax(heads.tool_action);
  // MCP tools have no code-known effect: only calls the model reads as read or list may skip the prompt.
  if (!action || (isMcpTool ? !MCP_ALLOWED_ACTIONS.has(action) : action !== expectedAction)) return prompt("tool_action_mismatch");
  const toolClass = argmax(heads.tool_class);
  if (!toolClass || RESTRICTED_TOOL_CLASSES.has(toolClass)) return prompt("tool_class_restricted");
  return { action: "allow", reason: "model_allow" };
}
