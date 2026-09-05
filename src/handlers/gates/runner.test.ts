import { describe, expect, it, vi } from "vitest";

import { runGateCheck } from "./runner";

describe("runGateCheck", () => {
  it("persists workspace approval patterns", async () => {
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
        approveSessionRule: vi.fn(),
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
    expect(persistPermissionRule).toHaveBeenCalledWith(
      "workspace",
      "bash",
      "git push *",
    );
  });
});
