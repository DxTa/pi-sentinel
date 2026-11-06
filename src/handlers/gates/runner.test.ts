import { describe, expect, it, vi } from "vitest";

import { takeDenyOverride } from "#src/deny-override";
import { runGateCheck } from "./runner";

describe("runGateCheck", () => {
  it("records gate checks and resolutions in the debug stream", async () => {
    const writeDebugLog = vi.fn();
    const result = await runGateCheck(
      {
        surface: "read",
        input: { path: "README.md" },
        denialContext: {
          kind: "tool",
          check: {
            toolName: "read",
            state: "allow",
            source: "tool",
            origin: "builtin",
          },
          input: { path: "README.md" },
        },
        promptDetails: {
          source: "tool_call",
          agentName: null,
          message: "Read README.md",
          toolName: "read",
        },
        logContext: {
          source: "tool_call",
          toolName: "read",
          command: "echo SECRET_TOKEN=do-not-log",
          message: "Run echo SECRET_TOKEN=do-not-log",
        },
        decision: { surface: "read", value: "README.md" },
        preCheck: {
          toolName: "read",
          state: "allow",
          source: "tool",
          origin: "builtin",
        },
      },
      null,
      "tool-1",
      {
        checkPermission: () => ({
          toolName: "read",
          state: "allow",
          source: "tool" as const,
          origin: "builtin" as const,
        }),
        getSessionRuleset: () => [],
        approveSessionRule: vi.fn(),
        persistPermissionRule: vi.fn(),
        writeReviewLog: vi.fn(),
        emitDecision: vi.fn(),
        canConfirm: () => false,
        promptPermission: vi.fn(),
        writeDebugLog,
      } as never,
    );

    expect(result).toEqual({ action: "allow" });
    expect(writeDebugLog).toHaveBeenCalledWith(
      "permission_gate.checked",
      expect.objectContaining({ surface: "read", state: "allow" }),
    );
    expect(writeDebugLog).toHaveBeenCalledWith(
      "permission_gate.resolved",
      expect.objectContaining({ action: "allow" }),
    );
    const debugRecords = writeDebugLog.mock.calls.map(([, details]) => details);
    expect(JSON.stringify(debugRecords)).not.toContain("SECRET_TOKEN=do-not-log");
  });

  it("prompts a fresh approval despite an existing session allow", async () => {
    const promptPermission = vi.fn(async () => ({ approved: true, state: "approved" as const }));
    const approveSessionRule = vi.fn();
    const persistPermissionRule = vi.fn();

    const result = await runGateCheck(
      {
        surface: "bash",
        input: { command: "git push origin main" },
        denialContext: {
          kind: "tool",
          check: {
            toolName: "bash",
            state: "allow",
            source: "session",
            origin: "session",
            command: "git push origin main",
          },
          input: { command: "git push origin main" },
        },
        freshApproval: true,
        promptDetails: {
          source: "tool_call",
          agentName: null,
          message: "Need permission",
          toolName: "bash",
          command: "git push origin main",
          allowSession: false,
          forcePromptInYolo: true,
        },
        logContext: {},
        decision: { surface: "bash", value: "git push origin main" },
        preCheck: {
          toolName: "bash",
          state: "allow",
          source: "session",
          origin: "session",
          command: "git push origin main",
        },
      },
      null,
      "tool-call-2",
      {
        checkPermission: vi.fn(),
        getSessionRuleset: () => [],
        approveSessionRule,
        persistPermissionRule,
        writeReviewLog: vi.fn(),
        emitDecision: vi.fn(),
        canConfirm: () => true,
        promptPermission,
      },
    );

    expect(result).toEqual({ action: "allow" });
    expect(promptPermission).toHaveBeenCalledOnce();
    expect(approveSessionRule).not.toHaveBeenCalled();
    expect(persistPermissionRule).not.toHaveBeenCalled();
  });

  it("persists workspace approval patterns and records them for current session", async () => {
    const approveSessionRule = vi.fn();
    const persistPermissionRule = vi.fn();

    const result = await runGateCheck(
      {
        surface: "bash",
        input: { command: "git push origin main" },
        denialContext: {
          kind: "tool",
          check: {
            toolName: "bash",
            state: "ask",
            source: "bash",
            origin: "builtin",
            command: "git push origin main",
          },
          input: { command: "git push origin main" },
        },
        sessionApproval: { surface: "bash", pattern: "git push *" },
        promptDetails: {
          source: "tool_call",
          agentName: null,
          message: "Need permission",
          toolName: "bash",
        },
        logContext: {},
        decision: { surface: "bash", value: "git push origin main" },
      },
      null,
      "tool-call-1",
      {
        checkPermission: () => ({
          toolName: "bash",
          state: "ask",
          source: "bash",
          origin: "builtin",
          command: "git push origin main",
        }),
        getSessionRuleset: () => [],
        approveSessionRule,
        persistPermissionRule,
        writeReviewLog: vi.fn(),
        emitDecision: vi.fn(),
        canConfirm: () => true,
        promptPermission: async () => ({
          approved: true,
          state: "approved_for_workspace",
        }),
      },
    );

    expect(result).toEqual({ action: "allow" });
    expect(approveSessionRule).toHaveBeenCalledWith("bash", "git push *");
    expect(persistPermissionRule).toHaveBeenCalledWith(
      "workspace",
      "bash",
      "git push *",
    );
  });

  describe("policy deny", () => {
    const denyCheck = { toolName: "bash", state: "deny" as const, source: "bash" as const, origin: "config" as const };
    const descriptor = {
      surface: "bash",
      input: { command: "cat /etc/hosts" },
      denialContext: { kind: "tool" as const, check: denyCheck, input: { command: "cat /etc/hosts" } },
      sessionApproval: { surface: "bash", pattern: "cat /etc/hosts*" },
      promptDetails: { source: "tool_call" as const, agentName: null, message: "Run cat", toolName: "bash" },
      logContext: { source: "tool_call", toolName: "bash" },
      decision: { surface: "bash", value: "cat /etc/hosts" },
      preCheck: denyCheck,
    };
    const makeDeps = (decision: unknown, canConfirm = true, yolo = false) => ({
      yolo,
      checkPermission: vi.fn(),
      getSessionRuleset: () => [],
      approveSessionRule: vi.fn(),
      persistPermissionRule: vi.fn(),
      writeReviewLog: vi.fn(),
      emitDecision: vi.fn(),
      canConfirm: () => canConfirm,
      promptPermission: vi.fn(async () => decision),
    });

    it("prompts once-or-session only, never auto-approved", async () => {
      const deps = makeDeps({ approved: true, state: "approved" });
      const result = await runGateCheck(descriptor as never, null, "t1", deps as never);
      expect(result).toEqual({ action: "allow" });
      expect(deps.promptPermission).toHaveBeenCalledWith(
        expect.objectContaining({ forcePromptInYolo: true, allowPersist: false }),
      );
      expect(deps.approveSessionRule).not.toHaveBeenCalled();
      expect(deps.emitDecision).toHaveBeenCalledWith(
        expect.objectContaining({ result: "allow", resolution: "user_approved" }),
      );
    });

    it("blocks without a dialog or override in yolo", async () => {
      const deps = makeDeps({ approved: true, state: "approved" }, true, true);
      const result = await runGateCheck(descriptor as never, null, "t-yolo", deps as never);
      expect(result.action).toBe("block");
      expect(deps.promptPermission).not.toHaveBeenCalled();
      expect(deps.writeReviewLog).not.toHaveBeenCalledWith("permission_request.deny_override_prompted", expect.anything());
      expect(takeDenyOverride("t-yolo")).toBe(false);
    });

    it("marks the tool call so the sandbox gate can issue a one-shot grant", async () => {
      const deps = makeDeps({ approved: true, state: "approved" });
      await runGateCheck(descriptor as never, null, "t-mark", deps as never);
      expect(takeDenyOverride("t-mark")).toBe(true);
    });

    it("does not mark a refused override", async () => {
      const deps = makeDeps({ approved: false, state: "denied" });
      await runGateCheck(descriptor as never, null, "t-nomark", deps as never);
      expect(takeDenyOverride("t-nomark")).toBe(false);
    });

    it("records a session rule when the user grants for the session", async () => {
      const deps = makeDeps({ approved: true, state: "approved_for_session" });
      await runGateCheck(descriptor as never, null, "t2", deps as never);
      expect(deps.approveSessionRule).toHaveBeenCalledWith("bash", "cat /etc/hosts*");
      expect(deps.persistPermissionRule).not.toHaveBeenCalled();
    });

    it("blocks when the user refuses", async () => {
      const deps = makeDeps({ approved: false, state: "denied" });
      const result = await runGateCheck(descriptor as never, null, "t3", deps as never);
      expect(result.action).toBe("block");
    });

    it("still blocks without UI", async () => {
      const deps = makeDeps({ approved: true, state: "approved" }, false);
      const result = await runGateCheck(descriptor as never, null, "t4", deps as never);
      expect(result.action).toBe("block");
      expect(deps.promptPermission).not.toHaveBeenCalled();
    });
  });
});
