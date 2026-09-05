import { describe, expect, it, vi } from "vitest";

import { applyPermissionGate } from "./permission-gate";

describe("applyPermissionGate", () => {
  it("returns workspace approval kind", async () => {
    const result = await applyPermissionGate({
      state: "ask",
      canConfirm: true,
      promptForApproval: async () => ({
        approved: true,
        state: "approved_for_workspace",
      }),
      writeLog: vi.fn(),
      logContext: {},
      messages: {
        denyReason: "deny",
        unavailableReason: "unavailable",
        userDeniedReason: () => "user denied",
      },
    });

    expect(result).toEqual({ action: "allow", approval: { kind: "workspace" } });
  });

  it("returns global approval kind", async () => {
    const result = await applyPermissionGate({
      state: "ask",
      canConfirm: true,
      promptForApproval: async () => ({
        approved: true,
        state: "approved_globally",
      }),
      writeLog: vi.fn(),
      logContext: {},
      messages: {
        denyReason: "deny",
        unavailableReason: "unavailable",
        userDeniedReason: () => "user denied",
      },
    });

    expect(result).toEqual({ action: "allow", approval: { kind: "global" } });
  });
});
