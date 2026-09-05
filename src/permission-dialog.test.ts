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
    ).resolves.toEqual({ approved: true, state: "approved_for_workspace" });
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
    ).resolves.toEqual({ approved: true, state: "approved_globally" });
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
});
