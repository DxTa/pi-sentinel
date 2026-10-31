import { describe, expect, it } from "vitest";
import { decideAutoMode, type AutoModeHeads, type AutoModePolicyInput } from "./auto-mode-policy";
import { AUTO_MODE_LABEL_SCHEMA as MODEL_LABELS } from "./auto-mode-label-schema";


function oneHot(labels: readonly string[], winner: string, p = 0.95): Record<string, number> {
  const rest = (1 - p) / (labels.length - 1);
  return Object.fromEntries(labels.map((label) => [label, label === winner ? p : rest]));
}

function distribution(labels: readonly string[], scores: Record<string, number>): Record<string, number> {
  return Object.fromEntries(labels.map((label) => [label, scores[label] ?? 0]));
}

function heads(overrides: Partial<AutoModeHeads> = {}, action = "read"): AutoModeHeads {
  return {
    injection: oneHot(MODEL_LABELS.injection, "benign", 0.98),
    threat: oneHot(MODEL_LABELS.threat, "benign"),
    tool_class: oneHot(MODEL_LABELS.tool_class, "file"),
    tool_action: oneHot(MODEL_LABELS.tool_action, action),
    tool_tags: { "source:sensitive": 0.1, "source:untrusted": 0.9, "sink:external": 0.1 },
    sensitive_document: oneHot(MODEL_LABELS.sensitive_document, "source_code"),
    routing: oneHot(MODEL_LABELS.routing, "tool_operation_request"),
    ...overrides,
  };
}

function input(overrides: Partial<AutoModePolicyInput> = {}): AutoModePolicyInput {
  return {
    enabled: true,
    permissionState: "ask",
    source: "tool_call",
    eligible: true,
    forcedPrompt: false,
    workspaceLocal: true,
    hardRuleHit: false,
    sandboxed: false,
    operation: "read",
    toolName: "read",
    heads: heads(),
    ...overrides,
  };
}

describe("decideAutoMode", () => {
  it.each([
    ["read", "read"],
    ["list", "list"],
    ["write", "write"],
    ["edit", "write"],
    ["exec", "exec"],
  ])("allows benign %s when tool_action is %s", (operation, action) => {
    expect(decideAutoMode(input({ operation, toolName: operation === "exec" ? "bash" : "read", sandboxed: operation === "exec", heads: heads({}, action) }))).toEqual({
      action: "allow",
      reason: "model_allow",
    });
  });

  it.each<[string, Partial<AutoModePolicyInput>]>([
    ["invalid_model_output", { heads: heads({ threat: { benign: Number.NaN } }) }],
    ["disabled", { enabled: false }],
    ["permission_state_not_ask", { permissionState: "deny" }],
    ["source_not_tool_call", { source: "bash" }],
    ["request_not_eligible", { eligible: false }],
    ["forced_prompt", { forcedPrompt: true }],
    ["path_not_workspace_local", { workspaceLocal: false }],
    ["sensitive_path", { hardRuleHit: true }],
    ["unsupported_operation", { operation: "network" }],
    ["model_unavailable", { heads: undefined }],
    ["threat_not_benign", { heads: heads({ threat: oneHot(MODEL_LABELS.threat, "secrets_access") }) }],
    ["threat_benign_low_confidence", { heads: heads({ threat: distribution(MODEL_LABELS.threat, { benign: 0.7, secrets_access: 0.3 }) }) }],
    ["injection_detected", { heads: heads({ injection: { benign: 0.7, injection: 0.3 } }) }],
    ["source_sensitive", { heads: heads({ tool_tags: { "source:sensitive": 0.6, "source:untrusted": 0, "sink:external": 0 } }) }],
    ["sink_external", { heads: heads({ tool_tags: { "source:sensitive": 0, "source:untrusted": 0, "sink:external": 0.6 } }) }],
    ["tool_action_mismatch", { heads: heads({}, "network") }],
    ["tool_class_restricted", { heads: heads({ tool_class: oneHot(MODEL_LABELS.tool_class, "secrets") }) }],
  ])("prompts with %s", (reason, overrides) => {
    expect(decideAutoMode(input(overrides))).toEqual({ action: "prompt", reason });
  });

  it.each<[string, Partial<AutoModeHeads>]>([
    ["incomplete source tags", { tool_tags: { "source:sensitive": 0.1, "sink:external": 0.1 } }],
    ["injection head replacing benign", { injection: { unexpected: 0.98, injection: 0.02 } }],
  ])("prompts for malformed head schema: %s", (_name, override) => {
    expect(decideAutoMode(input({ heads: heads(override) }))).toMatchObject({
      action: "prompt",
      reason: "invalid_model_output",
    });
  });

  it("allows the unknown tool class when all D10 gates pass", () => {
    const unknownClass = heads({ tool_class: oneHot(MODEL_LABELS.tool_class, "unknown") });
    expect(decideAutoMode(input({ heads: unknownClass }))).toEqual({
      action: "allow",
      reason: "model_allow",
    });
  });

  it("lets the model judge eligible unsandboxed exec", () => {
    expect(decideAutoMode(input({ operation: "exec", toolName: "bash", sandboxed: false })).reason).not.toBe("not_sandboxed");
  });

  it("prompts when exec is not from Bash", () => {
    expect(decideAutoMode(input({
      operation: "exec",
      toolName: "shell",
      sandboxed: true,
      heads: heads({}, "exec"),
    }))).toEqual({ action: "prompt", reason: "exec_not_bash" });
  });

  it.each([
    ["over-summed threat", distribution(MODEL_LABELS.threat, { benign: 0.95, secrets_access: 0.95 }), "invalid_model_output"],
    ["tied threat", distribution(MODEL_LABELS.threat, { benign: 0.5, secrets_access: 0.5 }), "threat_not_benign"],
    ["tied tool action", distribution(MODEL_LABELS.tool_action, { read: 0.5, write: 0.5 }), "tool_action_mismatch"],
  ])("fails closed for %s", (_name, override, reason) => {
    const key = _name === "tied threat" || _name === "over-summed threat" ? "threat" : "tool_action";
    expect(decideAutoMode(input({ heads: heads({ [key]: override }) }))).toMatchObject({ action: "prompt", reason });
  });

  it("prompts when read is classified as exec", () => {
    expect(decideAutoMode(input({ heads: heads({}, "exec") })).reason).toBe("tool_action_mismatch");
  });
});
