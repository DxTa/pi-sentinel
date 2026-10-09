import { describe, expect, it, vi } from "vitest";

import { PromptWaitTracker } from "./prompt-state";
import { PermissionPrompter } from "./permission-prompter";
import type { YoloAutoHeads } from "./yolo-auto-policy";
import { YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema";
import { workspaceScope } from "./yolo-auto-decision-store";

function oneHot(labels: readonly string[], winner: string): Record<string, number> {
  const rest = 0.01 / (labels.length - 1);
  return Object.fromEntries(labels.map((label) => [label, label === winner ? 0.99 : rest]));
}

const heads: YoloAutoHeads = {
  injection: oneHot(YOLO_AUTO_LABEL_SCHEMA.injection, "benign"),
  threat: oneHot(YOLO_AUTO_LABEL_SCHEMA.threat, "benign"),
  tool_class: oneHot(YOLO_AUTO_LABEL_SCHEMA.tool_class, "file"),
  tool_action: oneHot(YOLO_AUTO_LABEL_SCHEMA.tool_action, "read"),
  tool_tags: { "source:sensitive": 0.1, "source:untrusted": 0.9, "sink:external": 0.1 },
  sensitive_document: oneHot(YOLO_AUTO_LABEL_SCHEMA.sensitive_document, "source_code"),
  routing: oneHot(YOLO_AUTO_LABEL_SCHEMA.routing, "tool_operation_request"),
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
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "yolo-auto", yoloAskBashPatterns: [] }),
      yoloAutoEvaluator: { evaluate },
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
      yoloAutoEligible: true,
      yoloAutoHardRuleHit: false,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "write",
      yoloAutoWorkspaceRelativePath: "notes.txt",
    });

    expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({
      scope: workspaceScope("/work/repo"),
      patternKey: "write:./*.txt",
    }));
    expect(recordHumanDecision).toHaveBeenCalledWith("eval-human-1", action, expect.any(Number));
  });

  it("sends no pattern key for Bash whose inner commands cannot be read", async () => {
    const evaluate = vi.fn(async () => ({
      action: "prompt" as const, reason: "threat_not_benign", candidate: true, attempted: true,
      evaluationId: "eval-opaque-1", audit: false,
    }));
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "yolo-auto", yoloAskBashPatterns: [] }),
      yoloAutoEvaluator: { evaluate },
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: vi.fn(async () => ({ approved: true, state: "approved" as const })),
    });
    const bash = (command: string) => prompter.prompt({ hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never, {
      requestId: "req-opaque-1", source: "tool_call", agentName: null, message: "Need permission",
      toolName: "bash", command, yoloAutoEligible: true, yoloAutoHardRuleHit: false,
      yoloAutoWorkspaceLocal: true, yoloAutoOperation: "exec", yoloAutoText: "tool=bash command=x",
      yoloAutoUnits: command.startsWith("eval") ? ['eval "$x"'] : ["rm $f"], yoloAutoOpaque: command.startsWith("eval"),
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
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "yolo-auto", yoloAskBashPatterns: [] }),
      yoloAutoEvaluator: { evaluate: vi.fn(async () => ({
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
      yoloAutoEligible: true,
      yoloAutoHardRuleHit: false,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "write",
      yoloAutoWorkspaceRelativePath: "notes.txt",
    });

    expect(decision.approved).toBe(false);
    expect(recordHumanDecision).not.toHaveBeenCalled();
  });

  it("auto-allows workspace read-only Bash chains without the model or UI", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({ approved: true, state: "approved" as const }));
    const evaluate = vi.fn();
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({ debugLog: false, permissionReviewLog: false, mode: "yolo-auto", yoloAskBashPatterns: [] }),
      yoloAutoEvaluator: { evaluate }, writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents", forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });
    const context = { hasUI: true, cwd: process.cwd(), ui: { setStatus() {} } } as never;
    const common = {
      requestId: "req-chain", source: "tool_call" as const, agentName: null, message: "Need permission",
      toolName: "bash", yoloAutoEligible: false, yoloAutoWorkspaceLocal: true,
      yoloAutoHardRuleHit: false, yoloAutoSandboxed: false, yoloAutoOperation: "exec" as const,
    };

    await expect(prompter.prompt(context, { ...common, command: "cd src && ls && head -5 index.ts | grep x" }))
      .resolves.toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(evaluate).not.toHaveBeenCalled();

    await prompter.prompt(context, { ...common, command: "cd src && rm -rf out" });
    await prompter.prompt(context, { ...common, command: "cd .. && ls" });
    await prompter.prompt(context, { ...common, command: "cd src && ls", yoloAutoHardRuleHit: true });
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
      toolName: "bash", command: "docker port api 8501", yoloAutoWorkspaceLocal: true,
      yoloAutoHardRuleHit: false, yoloAutoSandboxed: false, yoloAutoOperation: "exec" as const,
    };
    const allowed = await prompter.prompt(context, details);
    const prompted = await prompter.prompt(context, { ...details, forcePromptInYolo: true });

    expect(allowed).toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(prompted).toEqual({ approved: true, state: "approved" });
    expect(ui).toHaveBeenCalledOnce();
  });

  it("allows listed Docker diagnostics in yolo-auto but honors configured prompts", async () => {
    const ui = vi.fn(async () => ({ approved: true, state: "approved" as const }));
    const base = {
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      writeReviewLog() {}, subagentSessionsDir: "/tmp/subagents", forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi: ui,
    };
    const context = { hasUI: true, cwd: "/work/repo", ui: { setStatus() {} } } as never;
    const prompter = new PermissionPrompter({
      ...base,
      getConfig: () => ({ debugLog: false, permissionReviewLog: true, mode: "yolo-auto", yoloAskBashPatterns: [] }),
    });
    const details = {
      requestId: "req-docker-ps", source: "tool_call" as const, agentName: null, message: "Need permission",
      toolName: "bash", command: "docker ps", yoloAutoEligible: false, yoloAutoWorkspaceLocal: true,
      yoloAutoHardRuleHit: false, yoloAutoSandboxed: false, yoloAutoOperation: "exec" as const,
    };
    const allowed = await prompter.prompt(context, details);
    expect(allowed).toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(ui).not.toHaveBeenCalled();

    const configured = new PermissionPrompter({
      ...base,
      getConfig: () => ({ debugLog: false, permissionReviewLog: true, mode: "yolo-auto", yoloAskBashPatterns: ["docker port *"] }),
    });
    const prompted = await configured.prompt(context, { ...details, command: "docker port api 8501" });
    expect(prompted).toEqual({ approved: true, state: "approved" });
    expect(ui).toHaveBeenCalledOnce();
  });

  it("uses model fallback for eligible workspace reads in yolo-auto", async () => {
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
        mode: "yolo-auto",
        yoloAskBashPatterns: [],
      }),
      yoloAutoClient: { evaluate },
      waitForYoloAutoStartup: async () => { startupOrder.push("startup"); },
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    const result = await prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-yolo-auto",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "read",
      yoloAutoEligible: true,
      yoloAutoHardRuleHit: false,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "read",
      yoloAutoWorkspaceRelativePath: "README.md",
    });

    expect(result).toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(startupOrder).toEqual(["startup", "evaluate"]);
    expect(evaluate).toHaveBeenCalledWith("tool=read path=README.md");
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.yolo_auto_approved",
    ]);
    expect(reviewLog[0]?.details).toMatchObject({
      evaluationId: "prompter-eval-1",
      yoloAutoAudit: false,
    });
  });

  it("adds evaluator metadata to yolo-auto approval entries", async () => {
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "yolo-auto",
        yoloAskBashPatterns: [],
      }),
      yoloAutoEvaluator: {
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
      requestId: "req-yolo-auto-allow",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "read",
      yoloAutoEligible: true,
      yoloAutoHardRuleHit: false,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "read",
      yoloAutoWorkspaceRelativePath: "README.md",
    });

    expect(reviewLog).toContainEqual(expect.objectContaining({
      event: "permission_request.yolo_auto_approved",
      details: expect.objectContaining({
        evaluationId: "prompter-eval-allow",
        yoloAutoAudit: false,
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
        mode: "yolo-auto",
        yoloAskBashPatterns: [],
      }),
      yoloAutoEvaluator: { evaluate },
      writeReviewLog(event, details) {
        reviewLog.push({ event, details });
      },
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    await prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-yolo-auto-write",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "write",
      yoloAutoEligible: true,
      yoloAutoHardRuleHit: false,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "write",
      yoloAutoWorkspaceRelativePath: "notes.txt",
      yoloAutoText: text,
      yoloAutoTextTruncated: true,
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
        yoloAutoAudit: false,
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
        mode: "yolo-auto",
        yoloAskBashPatterns: [],
      }),
      yoloAutoEvaluator: {
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
      requestId: "req-yolo-auto-audit",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "write",
      yoloAutoEligible: true,
      yoloAutoHardRuleHit: false,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "write",
      yoloAutoWorkspaceRelativePath: "notes.txt",
    });

    expect(reviewLog).toContainEqual(expect.objectContaining({
      event: "permission_request.approved",
      details: expect.objectContaining({
        evaluationId: "prompter-eval-audit",
        yoloAutoAudit: true,
      }),
    }));
  });

  it("prompts for non-candidate Bash calls in yolo-auto", async () => {
    const evaluate = vi.fn();
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: false,
      state: "denied" as const,
    }));
    const waitForYoloAutoStartup = vi.fn();
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        mode: "yolo-auto",
        yoloAskBashPatterns: [],
      }),
      yoloAutoClient: { evaluate },
      waitForYoloAutoStartup,
      writeReviewLog() {},
      subagentSessionsDir: "/tmp/subagents",
      forwardingDir: "/tmp/forwarding",
      requestPermissionDecisionFromUi,
    });

    await expect(prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
      requestId: "req-yolo-auto-classic",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "bash",
      command: "npm test",
    })).resolves.toEqual({ approved: false, state: "denied" });
    expect(waitForYoloAutoStartup).not.toHaveBeenCalled();
    expect(evaluate).not.toHaveBeenCalled();
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
  });

  it("falls back to prompt when yolo-auto startup fails", async () => {
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
        mode: "yolo-auto",
        yoloAskBashPatterns: [],
      }),
      yoloAutoClient: { evaluate },
      waitForYoloAutoStartup: async () => { throw new Error("worker unavailable"); },
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
      yoloAutoEligible: true,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "read",
      yoloAutoWorkspaceRelativePath: "README.md",
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

  it("prompts for matching bash yolo exceptions", async () => {
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

    expect(result).toEqual({ approved: true, state: "approved" });
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.waiting",
      "permission_request.approved",
    ]);
  });

  it("prompts when forcePromptInYolo is set for non-bash external writes", async () => {
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

    expect(result).toEqual({ approved: true, state: "approved" });
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.waiting",
      "permission_request.approved",
    ]);
  });

  it.each([
    "rm -rf /Volumes/NvmeExt1/openimages/OpenImages/.shards",
    "rm *",
  ])("prompts for destructive %s commands in YOLO mode", async (command: string) => {
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

    expect(result).toEqual({ approved: true, state: "approved" });
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.waiting",
      "permission_request.approved",
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


it("prompts for yolo-auto requests outside the model-eligible scope", async () => {
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
      mode: "yolo-auto",
      yoloAskBashPatterns: [],
    }),
    yoloAutoClient: { evaluate },
    writeReviewLog() {},
    subagentSessionsDir: "/tmp/subagents",
    forwardingDir: "/tmp/forwarding",
    requestPermissionDecisionFromUi,
  });

  await expect(prompter.prompt({ hasUI: true, ui: { setStatus() {} } } as never, {
    requestId: "req-yolo-auto-outside-scope",
    source: "tool_call",
    agentName: null,
    message: "Outside the model-eligible scope",
    toolName: "read",
    yoloAutoEligible: false,
    yoloAutoWorkspaceLocal: false,
    yoloAutoOperation: "read",
    yoloAutoWorkspaceRelativePath: "../outside.txt",
  })).resolves.toEqual({ approved: false, state: "denied" });

  expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
  expect(evaluate).not.toHaveBeenCalled();
});
