import { describe, expect, it, vi } from "vitest";

import { requestPermissionDecisionFromUi } from "./permission-dialog";

describe("requestPermissionDecisionFromUi", () => {
  it("returns workspace approval when workspace option selected", async () => {
    const ui = {
      select: vi.fn(async () => "Yes, for this workspace"),
      input: vi.fn(),
    };

    await expect(
      requestPermissionDecisionFromUi(ui, "Permission Required", "Allow?", {
        allowWorkspace: true,
      }),
    ).resolves.toEqual({ approved: true, state: "approved_for_workspace", humanDecided: true });
  });

  it("returns global approval when global option selected", async () => {
    const ui = {
      select: vi.fn(async () => "Yes, globally"),
      input: vi.fn(),
    };

    await expect(
      requestPermissionDecisionFromUi(ui, "Permission Required", "Allow?", {
        allowWorkspace: true,
      }),
    ).resolves.toEqual({ approved: true, state: "approved_globally", humanDecided: true });
  });

  it("omits workspace option when disabled", async () => {
    const ui = {
      select: vi.fn(async (_title: string, options: string[]) => {
        expect(options).not.toContain("Yes, for this workspace");
        return "Yes, globally";
      }),
      input: vi.fn(),
    };

    await requestPermissionDecisionFromUi(ui, "Permission Required", "Allow?", {
      allowWorkspace: false,
    });
  });

  it("marks an explicit No as a human decision", async () => {
    const ui = { select: vi.fn(async () => "No"), input: vi.fn() };
    await expect(requestPermissionDecisionFromUi(ui, "Permission Required", "Allow?"))
      .resolves.toEqual({ approved: false, state: "denied", humanDecided: true });
  });

  it("marks a denial with reason as a human decision", async () => {
    const ui = { select: vi.fn(async () => "No, provide reason"), input: vi.fn(async () => "too risky") };
    await expect(requestPermissionDecisionFromUi(ui, "Permission Required", "Allow?"))
      .resolves.toEqual({ approved: false, state: "denied_with_reason", denialReason: "too risky", humanDecided: true });
  });

  it("does not mark a dismissed dialog as a human decision", async () => {
    const ui = { select: vi.fn(async () => undefined), input: vi.fn() };
    await expect(requestPermissionDecisionFromUi(ui, "Permission Required", "Allow?"))
      .resolves.toEqual({ approved: false, state: "denied" });
  });
});
