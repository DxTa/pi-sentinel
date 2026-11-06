import { describe, expect, it, vi } from "vitest";

import { PromptWaitTracker } from "./prompt-state";
import { PermissionPrompter } from "./permission-prompter";
import { buildAutoModeText } from "./auto-mode-client";
import type { AutoModeHeads } from "./auto-mode-policy";
import { AUTO_MODE_LABEL_SCHEMA } from "./auto-mode-label-schema";
import { workspaceScope } from "./auto-mode-decision-store";

function oneHot(labels: readonly string[], winner: string): Record<string, number> {
  const rest = 0.01 / (labels.length - 1);
  return Object.fromEntries(labels.map((label) => [label, label === winner ? 0.99 : rest]));
}

const heads: AutoModeHeads = {
  injection: oneHot(AUTO_MODE_LABEL_SCHEMA.injection, "benign"),
  threat: oneHot(AUTO_MODE_LABEL_SCHEMA.threat, "benign"),
  tool_class: oneHot(AUTO_MODE_LABEL_SCHEMA.tool_class, "file"),
  tool_action: oneHot(AUTO_MODE_LABEL_SCHEMA.tool_action, "read"),
  tool_tags: { "source:sensitive": 0.1, "source:untrusted": 0.9, "sink:external": 0.1 },
  sensitive_document: oneHot(AUTO_MODE_LABEL_SCHEMA.sensitive_document, "source_code"),
  routing: oneHot(AUTO_MODE_LABEL_SCHEMA.routing, "tool_operation_request"),
}

describe("PermissionPrompter", () => {
  it.each([
    ["denied", "deny"],
    ["approved_for_session", "session"],
    ["approved_globally", "global"],
  ] as const)("records the human %s decision against the model evaluation", async (state, action) => {
    const evaluate = vi.fn(async () => ({
      action: "prompt" as const,
      reason: "threat_not_benign",
      candidate: true,
      attempted: true,
      evaluationId: "eval-human-1",
      audit: false,
    }));
    const recordHumanDecision = vi.fn();
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
      autoModeEvaluator: { evaluate },
      recordHumanDecision,
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: vi.fn(async () => ({ approved: state !== "denied", state, humanDecided: true as const })),
    });

    await prompter.prompt({ hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never, {
      requestId: "req-human-1",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "write",
      autoModeEligible: true,
      autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "write",
      autoModeWorkspaceRelativePath: "notes.txt",
    });

    expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({
      scope: workspaceScope("/work/repo"),
      patternKey: "write:./*.txt",
    }));
    expect(recordHumanDecision).toHaveBeenCalledWith("eval-human-1", action, expect.any(Number));
  });

  it("does not learn or offer remembered choices for one-time approval", async () => {
    const evaluate = vi.fn(async () => ({
      action: "prompt" as const,
      reason: "threat_not_benign",
      candidate: true,
      attempted: true,
      evaluationId: "eval-once-1",
      audit: false,
    }));
    const recordHumanDecision = vi.fn();
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
      humanDecided: true as const,
    }));
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
      autoModeEvaluator: { evaluate },
      recordHumanDecision,
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    await prompter.prompt({ hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never, {
      requestId: "req-once-1",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "bash",
      command: "git push origin main",
      allowSession: false,
      forcePromptInYolo: true,
      autoModeEligible: true,
      autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "exec",
    });

    expect(requestPermissionDecisionFromUi).toHaveBeenCalledWith(
      expect.anything(),
      "Permission Required",
      "Need permission",
      { allowSession: false, allowWorkspace: false, allowGlobal: false },
    );
    expect(recordHumanDecision).not.toHaveBeenCalled();
  });

  it("sends no pattern key for Bash whose inner commands cannot be read", async () => {
    const evaluate = vi.fn(async () => ({
      action: "prompt" as const, reason: "threat_not_benign", candidate: true, attempted: true,
      evaluationId: "eval-opaque-1", audit: false,
    }));
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
      autoModeEvaluator: { evaluate },
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: vi.fn(async () => ({ approved: true, state: "approved" as const })),
    });
    const bash = (command: string) => prompter.prompt({ hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never, {
      requestId: "req-opaque-1", source: "tool_call", agentName: null, message: "Need permission",
      toolName: "bash", command, autoModeEligible: true, autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true, autoModeOperation: "exec", autoModeText: "tool=bash command=x",
      autoModeUnits: command.startsWith("eval") ? ['eval "$x"'] : ["rm $f"], autoModeOpaque: command.startsWith("eval"),
    });

    await bash('eval "$x"');
    await bash("for f in a; do rm $f; done");
    expect(evaluate.mock.calls[1]![0]).toMatchObject({ units: ["rm $f"], opaque: false });
    expect(evaluate.mock.calls[0]![0]).not.toHaveProperty("patternKey");
    expect(evaluate.mock.calls[1]![0]).toMatchObject({ patternKey: "bash:rm *" });
  });

  it("does not label the evaluation when the decision did not come from a human answer", async () => {
    const recordHumanDecision = vi.fn();
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
      autoModeEvaluator: { evaluate: vi.fn(async () => ({
        action: "prompt" as const, reason: "threat_not_benign", candidate: true, attempted: true,
        evaluationId: "eval-system-1", audit: false,
      })) },
      recordHumanDecision,
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: vi.fn(async () => ({ approved: false, state: "denied" as const })),
    });

    const decision = await prompter.prompt({ hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never, {
      requestId: "req-system-1",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "write",
      autoModeEligible: true,
      autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "write",
      autoModeWorkspaceRelativePath: "notes.txt",
    });

    expect(decision.approved).toBe(false);
    expect(recordHumanDecision).not.toHaveBeenCalled();
  });

  it("auto-allows workspace read-only Bash chains without the model or UI", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({ approved: true, state: "approved" as const }));
    const evaluate = vi.fn(async () => ({
      action: "prompt" as const, reason: "not_eligible", candidate: false, attempted: false, evaluationId: "eval-chain", audit: false,
    }));
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
      autoModeEvaluator: { evaluate }, writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents", forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });
    const context = { hasUI: true, cwd: process.cwd(), ui: { setStatus() {} } } as never;
    const common = {
      requestId: "req-chain", source: "tool_call" as const, agentName: null, message: "Need permission",
      toolName: "bash", autoModeEligible: false, autoModeWorkspaceLocal: true,
      autoModeHardRuleHit: false, autoModeSandboxed: false, autoModeOperation: "exec" as const,
    };

    await expect(prompter.prompt(context, { ...common, command: "cd src && ls && head -5 index.ts | grep x" }))
      .resolves.toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(evaluate).not.toHaveBeenCalled();

    await prompter.prompt(context, { ...common, command: "cd src && rm -rf out" });
    await prompter.prompt(context, { ...common, command: "cd .. && ls" });
    await prompter.prompt(context, { ...common, command: "cd src && ls", autoModeHardRuleHit: true });
    await prompter.prompt(context, { ...common, command: "cd src && ls", forcePromptInYolo: true });
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledTimes(4);
  });

  it("auto-allows curated diagnostics in manual mode but still honors force-prompt", async () => {
    const ui = vi.fn(async () => ({ approved: true, state: "approved" as const }));
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: true, mode: "manual", yoloAskBashPatterns: [] }),
      writeReviewLog() {}, subagentSessionsDir: "/tmp/subagents", forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: ui,
    });
    const context = { hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never;
    const details = {
      requestId: "req-diagnostic", source: "tool_call" as const, agentName: null, message: "Need permission",
      toolName: "bash", command: "docker port api 8501", autoModeWorkspaceLocal: true,
      autoModeHardRuleHit: false, autoModeSandboxed: false, autoModeOperation: "exec" as const,
    };
    const allowed = await prompter.prompt(context, details);
    const prompted = await prompter.prompt(context, { ...details, forcePromptInYolo: true });

    expect(allowed).toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(prompted).toEqual({ approved: true, state: "approved" });
    expect(ui).toHaveBeenCalledOnce();
  });

  it("allows listed Docker diagnostics in auto but honors configured prompts", async () => {
    const ui = vi.fn(async () => ({ approved: true, state: "approved" as const }));
    const base = {
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      writeReviewLog() {}, subagentSessionsDir: "/tmp/subagents", forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: ui,
    };
    const context = { hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never;
    const prompter = new PermissionPrompter({
      ...base,
      getConfig: () => ({ debugLog: false, permissionReviewLog: true, mode: "auto", yoloAskBashPatterns: [] }),
    });
    const details = {
      requestId: "req-docker-ps", source: "tool_call" as const, agentName: null, message: "Need permission",
      toolName: "bash", command: "docker ps", autoModeEligible: false, autoModeWorkspaceLocal: true,
      autoModeHardRuleHit: false, autoModeSandboxed: false, autoModeOperation: "exec" as const,
    };
    const allowed = await prompter.prompt(context, details);
    expect(allowed).toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(ui).not.toHaveBeenCalled();

    const configured = new PermissionPrompter({
      ...base,
      getConfig: () => ({ debugLog: false, permissionReviewLog: true, mode: "auto", yoloAskBashPatterns: ["docker port *"] }),
    });
    const prompted = await configured.prompt(context, { ...details, command: "docker port api 8501" });
    expect(prompted).toEqual({ approved: true, state: "approved" });
    expect(ui).toHaveBeenCalledOnce();
  });

  it("uses model fallback for eligible workspace reads in auto", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));
    const startupOrder: string[] = [];
    const evaluate = vi.fn(async () => {
      startupOrder.push("evaluate");
      return {
        status: "complete" as const,
        evaluationId: "prompter-eval-1",
        buildId: "pi-sentinel-test:model-r1",
        totalLatencyMs: 5,
        heads,
      };
    });
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "auto",
        yoloAskBashPatterns: [],
      }),
      autoModeClient: { evaluate },
      waitForAutoModeStartup: async () => { startupOrder.push("startup"); },
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-auto",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "read",
      autoModeEligible: true,
      autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "read",
      autoModeWorkspaceRelativePath: "README.md",
    });

    expect(result).toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(startupOrder).toEqual(["startup", "evaluate"]);
    expect(evaluate).toHaveBeenCalledWith(buildAutoModeText({ toolName: "read", operation: "read", workspaceRelativePath: "README.md" }));
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.auto_mode_approved",
    ]);
    expect(reviewLog[0]?.details).toMatchObject({
      evaluationId: "prompter-eval-1",
      autoModeAudit: false,
    });
  });

  it("adds evaluator metadata to auto approval entries", async () => {
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "auto",
        yoloAskBashPatterns: [],
      }),
      autoModeEvaluator: {
        evaluate: vi.fn(async () => ({
          action: "allow" as const,
          reason: "thresholds_passed",
          candidate: true,
          attempted: true,
          evaluationId: "prompter-eval-allow",
          audit: false,
        })),
      },
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: vi.fn(async () => ({
        approved: true,
        state: "approved" as const,
      })),
    });

    await prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-auto-mode-allow",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "read",
      autoModeEligible: true,
      autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "read",
      autoModeWorkspaceRelativePath: "README.md",
    });

    expect(reviewLog).toContainEqual(expect.objectContaining({
      event: "permission_request.auto_mode_approved",
      details: expect.objectContaining({
        evaluationId: "prompter-eval-allow",
        autoModeAudit: false,
      }),
    }));
  });

  it("forwards prebuilt classifier text and truncation metadata", async () => {
    const text = "tool=write path=notes.txt content=preview";
    const evaluate = vi.fn(async () => ({
      action: "prompt" as const,
      reason: "tool_action_mismatch",
      candidate: true,
      attempted: true,
      evaluationId: "prompter-eval-write",
      audit: false,
    }));
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: false,
      state: "denied" as const,
    }));
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "auto",
        yoloAskBashPatterns: [],
      }),
      autoModeEvaluator: { evaluate },
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    await prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-auto-mode-write",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "write",
      autoModeEligible: true,
      autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "write",
      autoModeWorkspaceRelativePath: "notes.txt",
      autoModeText: text,
      autoModeTextTruncated: true,
    });

    expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({
      operation: "write",
      text,
      truncated: true,
      sandboxed: false,
    }));
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
    expect(reviewLog).toContainEqual(expect.objectContaining({
      event: "permission_request.denied",
      details: expect.objectContaining({
        evaluationId: "prompter-eval-write",
        autoModeAudit: false,
      }),
    }));
  });

  it("carries audit-sample identity into approval entries", async () => {
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "auto",
        yoloAskBashPatterns: [],
      }),
      autoModeEvaluator: {
        evaluate: vi.fn(async () => ({
          action: "prompt" as const,
          reason: "audit_sample",
          candidate: true,
          attempted: true,
          evaluationId: "prompter-eval-audit",
          audit: true,
        })),
      },
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: vi.fn(async () => ({
        approved: true,
        state: "approved" as const,
      })),
    });

    await prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-auto-mode-audit",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "write",
      autoModeEligible: true,
      autoModeHardRuleHit: false,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "write",
      autoModeWorkspaceRelativePath: "notes.txt",
    });

    expect(reviewLog).toContainEqual(expect.objectContaining({
      event: "permission_request.approved",
      details: expect.objectContaining({
        evaluationId: "prompter-eval-audit",
        autoModeAudit: true,
      }),
    }));
  });

  it("prompts for non-candidate Bash calls in auto", async () => {
    const evaluate = vi.fn();
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: false,
      state: "denied" as const,
    }));
    const waitForAutoModeStartup = vi.fn();
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "auto",
        yoloAskBashPatterns: [],
      }),
      autoModeClient: { evaluate },
      waitForAutoModeStartup,
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    await expect(prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-auto-mode-classic",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "bash",
      command: "npm test",
    })).resolves.toEqual({ approved: false, state: "denied" });
    expect(waitForAutoModeStartup).not.toHaveBeenCalled();
    expect(evaluate).not.toHaveBeenCalled();
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
  });

  it("falls back to prompt when auto startup fails", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: false,
      state: "denied" as const,
    }));
    const evaluate = vi.fn();
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "auto",
        yoloAskBashPatterns: [],
      }),
      autoModeClient: { evaluate },
      waitForAutoModeStartup: async () => { throw new Error("worker unavailable"); },
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    await expect(prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-startup-failure",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "read",
      autoModeEligible: true,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "read",
      autoModeWorkspaceRelativePath: "README.md",
    })).resolves.toEqual({ approved: false, state: "denied" });
    expect(evaluate).not.toHaveBeenCalled();
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
  });

  it("tracks prompt status for interactive permission approval", async () => {
    const statuses: Array<string | undefined> = [];
    const busEvents: Array<{ channel: string; payload: unknown }> = [];
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const tracker = new PromptWaitTracker({
      emit(channel, payload) {
        busEvents.push({ channel, payload });
      },
    });
    const ctx = {
      hasUI: true,
      ui: {
        setStatus(_key: string, value: string | undefined) {
          statuses.push(value);
        },
      },
    } as const;
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));

    const prompter = new PermissionPrompter({
      promptWaitTracker: tracker,
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "manual",
        yoloAskBashPatterns: [],
      }),
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt(ctx as never, {
      requestId: "req-1",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
    });

    expect(result).toEqual({ approved: true, state: "approved" });
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledWith(
      ctx.ui,
      "Permission Required",
      "Need permission",
      { allowWorkspace: false },
    );
    expect(statuses).toEqual([
      "Waiting for permission approval",
      undefined,
    ]);
    expect(busEvents).toEqual([
      {
        channel: "herdr:blocked",
        payload: { active: true, label: "Waiting for permission approval" },
      },
      {
        channel: "herdr:blocked",
        payload: { active: false, label: "Waiting for permission approval" },
      },
    ]);
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.waiting",
      "permission_request.approved",
    ]);
  });

  it("writes privacy-safe prompt debug records", async () => {
    const debugLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: true,
        permissionReviewLog: true,
        mode: "manual",
        yoloAskBashPatterns: [],
      }),
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: vi.fn(async () => ({
        approved: false,
        state: "denied" as const,
      })),
      writeDebugLog(event, details) {
        debugLog.push({ event, details });
      },
    } as never);

    await prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-debug",
      source: "tool_call",
      agentName: null,
      message: "Run command with secret-value",
      toolCallId: "tool-debug",
      toolName: "bash",
      command: "printf secret-value",
    });

    expect(debugLog.map(({ event }) => event)).toEqual([
      "permission_prompt.requested",
      "permission_prompt.resolved",
    ]);
    expect(debugLog[0]?.details).toMatchObject({
      requestId: "req-debug",
      toolName: "bash",
      messageLength: expect.any(Number),
    });
    expect(JSON.stringify(debugLog)).not.toContain("secret-value");
  });

  it("auto-approves yolo requests when no bash exception matches", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];

    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "yolo",
        yoloAskBashPatterns: [],
      }),
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt({ hasUI: true, ui: {} } as never, {
      requestId: "req-2",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "bash",
      command: "npm test",
    });

    expect(result).toEqual({
      approved: true,
      state: "approved",
      autoApproved: true,
    });
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.auto_approved",
    ]);
  });

  it("blocks matching bash yolo exceptions without a dialog", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];

    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "yolo",
        yoloAskBashPatterns: ["git push *"],
      } as any),
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt({
      hasUI: true,
      ui: {
        setStatus() {},
      },
    } as never, {
      requestId: "req-3",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "bash",
      command: "git push origin main",
    });

    expect(result).toMatchObject({ approved: false, state: "denied" });
    expect(result.denialReason).toContain("yolo");
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.yolo_blocked",
    ]);
  });

  it("blocks forcePromptInYolo non-bash external writes without a dialog", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];

    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "yolo",
        yoloAskBashPatterns: [],
      }),
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt({
      hasUI: true,
      ui: {
        setStatus() {},
      },
    } as never, {
      requestId: "req-4",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "write",
      path: "../notes.txt",
      forcePromptInYolo: true,
    } as any);

    expect(result).toMatchObject({ approved: false, state: "denied" });
    expect(result.denialReason).toContain("yolo");
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.yolo_blocked",
    ]);
  });

  it.each([
    "rm -rf /Volumes/NvmeExt1/openimages/OpenImages/.shards",
    "rm *",
  ])("blocks destructive %s commands in YOLO mode without a dialog", async (command: string) => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];

    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "yolo",
        yoloAskBashPatterns: [],
      }),
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt({
      hasUI: true,
      ui: {
        setStatus() {},
      },
    } as never, {
      requestId: `rm-${command}`,
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "bash",
      command,
    });

    expect(result).toMatchObject({ approved: false, state: "denied" });
    expect(result.denialReason).toContain("yolo");
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.yolo_blocked",
    ]);
  });

  it("still auto-approves non-bash requests with bash-only exceptions configured", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));

    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "yolo",
        yoloAskBashPatterns: ["git push *"],
      } as any),
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt({ hasUI: true, ui: {} } as never, {
      requestId: "req-5",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "read",
      path: "README.md",
    });

    expect(result).toEqual({
      approved: true,
      state: "approved",
      autoApproved: true,
    });
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });
});


it("prompts for auto requests outside the model-eligible scope", async () => {
  const requestPermissionDecisionFromUi = vi.fn(async () => ({
    approved: false,
    state: "denied" as const,
  }));
  const evaluate = vi.fn();
  const prompter = new PermissionPrompter({
    promptWaitTracker: new PromptWaitTracker({ emit() {} }),
    getConfig: () => ({
      debugLog: false,
      permissionReviewLog: true,
      mode: "auto",
      yoloAskBashPatterns: [],
    }),
    autoModeClient: { evaluate },
    writeReviewLog() {},
    subagentSessionsDir: "/tmp/subagents",
    forwardingDir: "/tmp/forwarding",
    requestPermissionDecisionFromUi,
  });

  await expect(prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
    requestId: "req-auto-mode-outside-scope",
    source: "tool_call",
    agentName: null,
    message: "Outside the model-eligible scope",
    toolName: "read",
    autoModeEligible: false,
    autoModeWorkspaceLocal: false,
    autoModeOperation: "read",
    autoModeWorkspaceRelativePath: "../outside.txt",
  })).resolves.toEqual({ approved: false, state: "denied" });

  expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
  expect(evaluate).not.toHaveBeenCalled();
});

it.each([
  ["not_eligible", { autoModeWorkspaceLocal: true }],
] as const)("logs a %s skip through the evaluator in auto instead of silently prompting", async (skipReason, scope) => {
  const requestPermissionDecisionFromUi = vi.fn(async () => ({
    approved: false,
    state: "denied" as const,
  }));
  const evaluate = vi.fn(async () => ({
    action: "prompt" as const,
    reason: skipReason,
    candidate: false,
    attempted: false,
    evaluationId: "eval-skip-1",
    audit: false,
  }));
  const prompter = new PermissionPrompter({
    promptWaitTracker: new PromptWaitTracker({ emit() {} }),
    getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
    autoModeEvaluator: { evaluate },
    writeReviewLog() {},
    subagentSessionsDir: "/tmp/subagents",
    forwardingDir: "/tmp/forwarding",
    requestPermissionDecisionFromUi,
  });

  await expect(prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
    requestId: `req-auto-skip-${skipReason}`,
    source: "tool_call",
    agentName: null,
    message: "Need permission",
    toolName: "bash",
    command: "npm test",
    autoModeEligible: false,
    autoModeHardRuleHit: false,
    autoModeOperation: "exec",
    ...scope,
  })).resolves.toEqual({ approved: false, state: "denied" });

  expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({ candidate: false, skipReason }));
  expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
});

describe("auto mode sends forced prompts to the model", () => {
  it.each(["rm build.txt", "npm publish", "cd src && ssh host", "kubectl -n prod delete pod a"])(
    "approves %s when the model allows",
    async (command) => {
      const evaluate = vi.fn(async () => ({
        action: "allow" as const, reason: "model_allow", candidate: true, attempted: true, evaluationId: "e", audit: false,
      }));
      const requestPermissionDecisionFromUi = vi.fn(async () => ({ approved: false, state: "denied" as const }));
      const prompter = new PermissionPrompter({
        promptWaitTracker: new PromptWaitTracker({ emit() {} }),
        getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
        autoModeEvaluator: { evaluate },
        writeReviewLog() {},
        subagentSessionsDir: "/tmp/subagents",
        forwardingDir: "/tmp/forwarding",
        requestPermissionDecisionFromUi,
      });
      const result = await prompter.prompt({ hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never, {
        requestId: "r", source: "tool_call", agentName: null, message: "Need permission", toolName: "bash", command,
        autoModeEligible: true, autoModeHardRuleHit: false, autoModeWorkspaceLocal: true, autoModeOperation: "exec",
        autoModeText: "tool=bash command=" + command,
      });
      expect(evaluate.mock.calls[0]![0]).toMatchObject({ forcedPrompt: true });
      expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
      expect(result.approved).toBe(true);
    },
  );
});

it("sends a non-local eligible request to the model as a candidate", async () => {
  const evaluate = vi.fn(async () => ({
    action: "allow" as const, reason: "model_allow", candidate: true, attempted: true, evaluationId: "e", audit: false,
  }));
  const requestPermissionDecisionFromUi = vi.fn(async () => ({ approved: false, state: "denied" as const }));
  const prompter = new PermissionPrompter({
    promptWaitTracker: new PromptWaitTracker({ emit() {} }),
    getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "auto", yoloAskBashPatterns: [] }),
    autoModeEvaluator: { evaluate },
    writeReviewLog() {},
    subagentSessionsDir: "/tmp/subagents",
    forwardingDir: "/tmp/forwarding",
    requestPermissionDecisionFromUi,
  });
  const result = await prompter.prompt({ hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never, {
    requestId: "r-nonlocal", source: "tool_call", agentName: null, message: "Need permission", toolName: "write",
    autoModeEligible: true, autoModeHardRuleHit: false, autoModeWorkspaceLocal: false, autoModeOperation: "write",
  });
  expect(evaluate.mock.calls[0]![0]).toMatchObject({ candidate: true, workspaceLocal: false });
  expect(result.approved).toBe(true);
  expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
});

describe("yolo mode sends external writes and exec to the model", () => {
  const modelResult = (action: "allow" | "prompt", reason = "threat_not_benign") => ({
    action, reason: action === "allow" ? "model_allow" : reason, candidate: true, attempted: true, evaluationId: "e", audit: false,
  });
  const setup = (action: "allow" | "prompt" | undefined, reason?: string) => {
    const evaluate = vi.fn(async () => modelResult(action ?? "prompt", reason));
    const requestPermissionDecisionFromUi = vi.fn(async () => ({ approved: false, state: "denied" as const }));
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "yolo", yoloAskBashPatterns: [] }),
      ...(action ? { autoModeEvaluator: { evaluate } } : {}),
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });
    const run = (details: Record<string, unknown>) => prompter.prompt(
      { hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never,
      { requestId: "r-yolo", source: "tool_call", agentName: null, message: "Need permission", ...details } as never,
    );
    return { evaluate, requestPermissionDecisionFromUi, run };
  };
  const externalWrite = {
    toolName: "write", autoModeOperation: "write", autoModeEligible: true, autoModeWorkspaceLocal: false, autoModeHardRuleHit: false,
  };

  it("approves an external write the model allows", async () => {
    const { evaluate, requestPermissionDecisionFromUi, run } = setup("allow");
    expect((await run(externalWrite)).approved).toBe(true);
    expect(evaluate).toHaveBeenCalledOnce();
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });

  it.each(["threat_not_benign", "injection_detected"])("blocks an external write the model flags as %s", async (reason) => {
    const { requestPermissionDecisionFromUi, run } = setup("prompt", reason);
    const result = await run(externalWrite);
    expect(result).toMatchObject({ approved: false, state: "denied" });
    expect(result.denialReason).toContain(reason);
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });

  it("allows injection_detected when every operand stays in the workspace", async () => {
    const { requestPermissionDecisionFromUi, run } = setup("prompt", "injection_detected");
    const result = await run({ ...externalWrite, toolName: "bash", command: "cat > a.ts", autoModeOperation: "exec", autoModeTargetsWorkspace: true });
    expect(result.approved).toBe(true);
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });

  it("still blocks threat_not_benign for a workspace write", async () => {
    const { run } = setup("prompt", "threat_not_benign");
    const result = await run({ ...externalWrite, autoModeTargetsWorkspace: true });
    expect(result.approved).toBe(false);
  });

  it.each(["too_many_units", "unit_too_long", "threat_benign_low_confidence", "startup_failed", "worker_unavailable"])(
    "allows an external write when the model result is %s",
    async (reason) => {
      const { requestPermissionDecisionFromUi, run } = setup("prompt", reason);
      expect((await run(externalWrite)).approved).toBe(true);
      expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    },
  );

  it("allows an external write when no classifier is configured", async () => {
    const { requestPermissionDecisionFromUi, run } = setup(undefined);
    expect((await run(externalWrite)).approved).toBe(true);
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });

  it("sends external exec to the model", async () => {
    const { evaluate, run } = setup("allow");
    const result = await run({
      toolName: "bash", command: "npm test", autoModeOperation: "exec", autoModeEligible: true, autoModeWorkspaceLocal: false, autoModeHardRuleHit: false,
    });
    expect(result.approved).toBe(true);
    expect(evaluate).toHaveBeenCalledOnce();
  });

  it.each([
    ["a workspace write", { ...externalWrite, autoModeWorkspaceLocal: true }],
    ["a non-sensitive external read", { toolName: "read", autoModeOperation: "read", autoModeEligible: true, autoModeWorkspaceLocal: false, autoModeHardRuleHit: false }],
    ["a pathless tool", { toolName: "mcp__x__y" }],
  ])("approves %s without the model", async (_name, details) => {
    const { evaluate, requestPermissionDecisionFromUi, run } = setup("prompt");
    expect((await run(details)).approved).toBe(true);
    expect(evaluate).not.toHaveBeenCalled();
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });

  it("blocks a sensitive external read without the model or a dialog", async () => {
    const { evaluate, requestPermissionDecisionFromUi, run } = setup("allow");
    const result = await run({ toolName: "read", autoModeOperation: "read", autoModeEligible: true, autoModeWorkspaceLocal: false, autoModeHardRuleHit: true });
    expect(result).toMatchObject({ approved: false, state: "denied" });
    expect(evaluate).not.toHaveBeenCalled();
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });

  it("blocks forced prompts without the model or a dialog", async () => {
    const { evaluate, requestPermissionDecisionFromUi, run } = setup("allow");
    const result = await run({ ...externalWrite, toolName: "bash", command: "rm -rf build", autoModeOperation: "exec" });
    expect(result).toMatchObject({ approved: false, state: "denied" });
    expect(evaluate).not.toHaveBeenCalled();
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
  });
});
