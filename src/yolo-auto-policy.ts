import type { PermissionState } from "./types";

const REQUIRED_CATEGORIES = ["injection", "tool_class", "tool_action", "tool_tags"] as const;
const REQUIRED_TAG_PIPELINES = ["source_sensitive", "source_untrusted", "sink_external"] as const;

type RequiredCategory = (typeof REQUIRED_CATEGORIES)[number];
type RequiredTagPipeline = (typeof REQUIRED_TAG_PIPELINES)[number];

export type YoloAutoL1Verdict = "safe" | "unsafe" | "unknown";

export interface YoloAutoL1Response {
  verdict: YoloAutoL1Verdict;
  accepted: boolean;
  complete: boolean;
  degraded: boolean;
  provenance?: string;
}

export interface YoloAutoClassifierResult {
  category: string;
  className: string;
  pipeline?: string;
  accepted: boolean;
  complete: boolean;
  degraded: boolean;
  provenance?: string;
}

export interface YoloAutoPolicyInput {
  enabled: boolean;
  maxLevel: "l1" | "l2" | "l3";
  permissionState: PermissionState;
  source: string;
  eligible: boolean;
  forcedPrompt: boolean;
  workspaceLocal: boolean;
  operation: string;
  l1: YoloAutoL1Response | undefined;
  results: readonly YoloAutoClassifierResult[];
  escalated: boolean;
}

export interface YoloAutoPolicyDecision {
  action: "allow" | "prompt";
  reason: string;
}

function prompt(reason: string): YoloAutoPolicyDecision {
  return { action: "prompt", reason };
}

function normalizeTagPipeline(pipeline: string | undefined): RequiredTagPipeline | undefined {
  if (!pipeline) return undefined;
  const normalized = pipeline.toLowerCase().replaceAll("-", "_");
  return REQUIRED_TAG_PIPELINES.find((name) =>
    normalized === name || normalized.endsWith(`_${name}`),
  );
}

function hasAcceptedCompleteResult(
  results: readonly YoloAutoClassifierResult[],
  category: RequiredCategory,
  className: string,
): boolean {
  const matches = results.filter((result) => result.category === category);
  return matches.length === 1
    && matches[0].className === className
    && matches[0].accepted
    && matches[0].complete
    && !matches[0].degraded;
}

function isSafeL1(l1: YoloAutoL1Response | undefined): boolean {
  return l1?.verdict === "safe"
    && l1.accepted
    && l1.complete
    && !l1.degraded;
}

export function decideYoloAuto(input: YoloAutoPolicyInput): YoloAutoPolicyDecision {
  if (!input.enabled) return prompt("disabled");
  if (input.permissionState !== "ask") return prompt("permission_state_not_ask");
  if (input.source !== "tool_call") return prompt("source_not_tool_call");
  if (!input.eligible) return prompt("request_not_eligible");
  if (input.forcedPrompt) return prompt("forced_prompt");
  if (!input.workspaceLocal) return prompt("path_not_workspace_local");
  if (input.operation !== "read" && input.operation !== "list") {
    return prompt("operation_not_read_or_list");
  }
  if (!isSafeL1(input.l1)) return prompt("l1_not_safe");
  if (input.maxLevel === "l1") {
    return {
      action: "allow",
      reason: input.operation === "read" ? "safe_workspace_read" : "safe_workspace_list",
    };
  }
  if (input.escalated) return prompt("l3_escalation_requires_review");
  if (input.results.some((result) => !REQUIRED_CATEGORIES.includes(result.category as RequiredCategory))) {
    return prompt("unknown_classifier_category");
  }
  if (!hasAcceptedCompleteResult(input.results, "injection", "safe")) {
    return prompt("injection_not_safe");
  }
  if (!hasAcceptedCompleteResult(input.results, "tool_class", "file")) {
    return prompt("tool_class_not_file");
  }
  if (!hasAcceptedCompleteResult(input.results, "tool_action", input.operation)) {
    return prompt("tool_action_mismatch");
  }

  for (const pipeline of REQUIRED_TAG_PIPELINES) {
    const matches = input.results.filter((result) =>
      result.category === "tool_tags" && normalizeTagPipeline(result.pipeline) === pipeline,
    );
    if (matches.length !== 1) return prompt("tool_tags_incomplete");
    const result = matches[0];
    if (result.className !== "absent" || !result.accepted || !result.complete || result.degraded) {
      return prompt("unsafe_tool_tag");
    }
  }

  return {
    action: "allow",
    reason: input.operation === "read" ? "safe_workspace_read" : "safe_workspace_list",
  };
}
