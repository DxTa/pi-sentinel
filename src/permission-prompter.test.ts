import { describe, expect, it, vi } from "vitest";

import { PromptWaitTracker } from "./prompt-state";
import { PermissionPrompter } from "./permission-prompter";

describe("PermissionPrompter", () => {
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
