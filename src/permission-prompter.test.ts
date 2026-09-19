import { describe, expect, it, vi } from "vitest";

import { PromptWaitTracker } from "./prompt-state";
import { PermissionPrompter } from "./permission-prompter";

describe("PermissionPrompter", () => {
  it("auto-approves eligible safe workspace reads through yolo-auto", async () => {
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved" as const,
    }));
    const startupOrder: string[] = [];
    const evaluate = vi.fn(async () => {
      startupOrder.push("evaluate");
      return {
      status: "complete" as const,
      escalated: false,
      l1: { verdict: "safe" as const, accepted: true, complete: true, degraded: false },
      l2: {
        escalated: false,
        results: [
          { category: "injection", className: "safe", accepted: true, complete: true, degraded: false },
          { category: "tool_class", className: "file", accepted: true, complete: true, degraded: false },
          { category: "tool_action", className: "read", accepted: true, complete: true, degraded: false },
          ...["source_sensitive", "source_untrusted", "sink_external"].map((pipeline) => ({
            category: "tool_tags",
            pipeline,
            className: "absent",
            accepted: true,
            complete: true,
            degraded: false,
          })),
        ],
      },
      l3: undefined,
      };
    });
    const reviewLog: Array<{ event: string; details: Record<string, unknown> }> = [];
    const prompter = new PermissionPrompter({
      promptWaitTracker: new PromptWaitTracker({ emit() {} }),
      getConfig: () => ({
        debugLog: false,
        permissionReviewLog: true,
        yoloMode: false,
        yoloAutoMode: true,
        yoloAutoMaxLevel: "l2",
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

    const result = await prompter.prompt({ hasUI: true, ui: {} } as never, {
      requestId: "req-yolo-auto",
      source: "tool_call",
      agentName: null,
      message: "Need permission",
      toolName: "read",
      path: "README.md",
      yoloAutoEligible: true,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "read",
      yoloAutoWorkspaceRelativePath: "README.md",
    });

    expect(result).toEqual({ approved: true, state: "approved", autoApproved: true });
    expect(startupOrder).toEqual(["startup", "evaluate"]);
    expect(evaluate).toHaveBeenCalledWith({
      toolName: "read",
      operation: "read",
      workspaceRelativePath: "README.md",
      metadata: { input_has_path: true, tool_call_id_present: false },
    }, "l2");
    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(reviewLog.map((entry) => entry.event)).toEqual([
      "permission_request.yolo_auto_approved",
    ]);
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
        yoloMode: false,
        yoloAutoMode: true,
        yoloAutoMaxLevel: "l2",
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
        yoloMode: false,
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
        yoloMode: true,
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
        yoloMode: true,
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
        yoloMode: true,
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
        yoloMode: true,
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
        yoloMode: true,
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
