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
    ["sensitive_path", { hardRuleHit: true }],
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

  it("lets the model judge exec from any tool and operations without an expected action", () => {
    expect(decideAutoMode(input({ operation: "exec", toolName: "shell", heads: heads({}, "exec") })).action).toBe("allow");
    expect(decideAutoMode(input({ operation: "network", toolName: "fetch" })).action).toBe("allow");
  });

  it("judges a non-explicit allow state like ask", () => {
    expect(decideAutoMode(input({ permissionState: "allow" })).action).toBe("allow");
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

describe("per-operation thresholds", () => {
  const strict = { minBenignThreat: 0.99, maxInjection: 0.25, maxToolTag: 0.5 };
  const loose = { minBenignThreat: 0.5, maxInjection: 0.25, maxToolTag: 0.5 };
  const benign90 = (action: string) => heads({ threat: distribution(MODEL_LABELS.threat, { benign: 0.9, tool_abuse: 0.1 }) }, action);

  it("uses the operation's own set before the default", () => {
    const thresholds = { default: loose, exec: strict };
    expect(decideAutoMode(input({ operation: "write", toolName: "write", heads: benign90("write"), thresholds })).action).toBe("allow");
    expect(decideAutoMode(input({ operation: "exec", toolName: "bash", heads: benign90("exec"), thresholds }))).toEqual({
      action: "prompt",
      reason: "threat_benign_low_confidence",
    });
  });

  it("falls back to the default set for operations without an entry", () => {
    expect(decideAutoMode(input({ heads: benign90("read"), thresholds: { default: strict } })).reason).toBe("threat_benign_low_confidence");
  });

  it("keeps today's values as the profile default", () => {
    expect(decideAutoMode(input({ heads: benign90("read") })).action).toBe("allow");
    expect(decideAutoMode(input({ heads: heads({ threat: distribution(MODEL_LABELS.threat, { benign: 0.7, tool_abuse: 0.3 }) }) })).reason)
      .toBe("threat_benign_low_confidence");
  });
});

describe("MCP tool operation", () => {
  const mcp = (action: string, toolName = "mcp__github__get_issue") =>
    input({ operation: "tool", toolName, heads: heads({ tool_class: oneHot(MODEL_LABELS.tool_class, "api") }, action) });

  it.each(["read", "list"])("allows a benign MCP call the model reads as %s", (action) => {
    expect(decideAutoMode(mcp(action))).toEqual({ action: "allow", reason: "model_allow" });
  });

  it.each(["write", "exec", "network", "unknown"])("prompts an MCP call the model reads as %s", (action) => {
    expect(decideAutoMode(mcp(action))).toEqual({ action: "prompt", reason: "tool_action_mismatch" });
  });

  it("prompts the tool operation for tools not named like MCP tools", () => {
    expect(decideAutoMode(mcp("read", "codemode"))).toEqual({ action: "prompt", reason: "tool_not_mcp" });
  });

  it("still applies injection and restricted-class checks", () => {
    expect(decideAutoMode({ ...mcp("read"), heads: heads({ injection: { benign: 0.4, injection: 0.6 } }, "read") }).reason)
      .toBe("injection_detected");
    expect(decideAutoMode({ ...mcp("read"), heads: heads({ tool_class: oneHot(MODEL_LABELS.tool_class, "infra") }, "read") }).reason)
      .toBe("tool_class_restricted");
  });
});
