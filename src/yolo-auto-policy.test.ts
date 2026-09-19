import { describe, expect, it } from "vitest";

import { decideYoloAuto, type YoloAutoClassifierResult, type YoloAutoL1Response } from "./yolo-auto-policy";

const safeL1: YoloAutoL1Response = {
  verdict: "safe",
  accepted: true,
  complete: true,
  degraded: false,
};

const safeResults: YoloAutoClassifierResult[] = [
  { category: "injection", className: "safe", complete: true, degraded: false, accepted: true },
  { category: "tool_class", className: "file", complete: true, degraded: false, accepted: true },
  { category: "tool_action", className: "read", complete: true, degraded: false, accepted: true },
  { category: "tool_tags", className: "absent", pipeline: "source_sensitive", complete: true, degraded: false, accepted: true },
  { category: "tool_tags", className: "absent", pipeline: "source_untrusted", complete: true, degraded: false, accepted: true },
  { category: "tool_tags", className: "absent", pipeline: "sink_external", complete: true, degraded: false, accepted: true },
];

function policy(overrides: Partial<Parameters<typeof decideYoloAuto>[0]> = {}) {
  return {
    enabled: true,
    maxLevel: "l2" as const,
    permissionState: "ask" as const,
    source: "tool_call" as const,
    eligible: true,
    forcedPrompt: false,
    workspaceLocal: true,
    operation: "read",
    l1: safeL1,
    results: safeResults,
    escalated: false,
    ...overrides,
  };
}

describe("decideYoloAuto", () => {
  it("allows safe L1 workspace-local reads", () => {
    expect(decideYoloAuto(policy({ maxLevel: "l1" }))).toEqual({ action: "allow", reason: "safe_workspace_read" });
  });

  it("requires safe L1 before L2 approval", () => {
    expect(decideYoloAuto(policy({ l1: { ...safeL1, verdict: "unsafe" } }))).toMatchObject({ action: "prompt", reason: "l1_not_safe" });
    expect(decideYoloAuto(policy({ l1: undefined }))).toMatchObject({ action: "prompt", reason: "l1_not_safe" });
  });

  it("allows complete safe workspace-local reads at L2", () => {
    expect(decideYoloAuto(policy())).toEqual({ action: "allow", reason: "safe_workspace_read" });
  });

  it("allows complete safe workspace-local lists at L2", () => {
    expect(decideYoloAuto(policy({ operation: "list", results: safeResults.map((result) =>
      result.category === "tool_action" ? { ...result, className: "list" } : result,
    ) }))).toEqual({ action: "allow", reason: "safe_workspace_list" });
  });

  it.each([
    ["disabled mode", { enabled: false }],
    ["non-ask state", { permissionState: "allow" }],
    ["non-tool source", { source: "skill_input" }],
    ["ineligible request", { eligible: false }],
    ["forced prompt", { forcedPrompt: true }],
    ["external path", { workspaceLocal: false }],
    ["write operation", { operation: "write" }],
    ["L3 escalation", { escalated: true }],
  ] as const)("prompts for %s", (_name, overrides) => {
    expect(decideYoloAuto(policy(overrides))).toMatchObject({ action: "prompt" });
  });

  it("prompts when any required L2 classifier result is missing or degraded", () => {
    expect(decideYoloAuto(policy({ results: safeResults.slice(0, -1) }))).toMatchObject({ action: "prompt" });
    expect(decideYoloAuto(policy({ results: safeResults.map((result, index) =>
      index === 0 ? { ...result, degraded: true } : result,
    ) }))).toMatchObject({ action: "prompt" });
  });

  it.each([
    ["unsafe injection", { category: "injection", className: "instruction_override" }],
    ["wrong class", { category: "tool_class", className: "shell" }],
    ["unsafe tag", { category: "tool_tags", pipeline: "source_untrusted", className: "present" }],
    ["unknown action", { category: "tool_action", className: "unknown" }],
  ] as const)("prompts for %s", (_name, result) => {
    const results = safeResults.map((candidate) =>
      candidate.category === result.category &&
      (result.pipeline === undefined || candidate.pipeline === result.pipeline)
        ? { ...candidate, ...result }
        : candidate,
    );
    expect(decideYoloAuto(policy({ results }))).toMatchObject({ action: "prompt" });
  });
});
