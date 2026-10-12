import { describe, expect, it } from "vitest";

import { DEFAULT_EXTENSION_CONFIG } from "./extension-config";

describe("permission mode settings", () => {
  it("offers one mode selector with manual, yolo, and yolo-auto", async () => {
    const modal = await import("./config-modal") as unknown as Record<string, unknown>;
    expect(typeof modal.buildSettingItems).toBe("function");

    const buildSettingItems = modal.buildSettingItems as (config: unknown) => Array<Record<string, unknown>>;
    const [mode] = buildSettingItems({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" });

    expect(mode).toMatchObject({
      id: "mode",
      label: "Mode",
      currentValue: "manual",
      values: ["manual", "yolo", "yolo-auto"],
    });
  });

  it("keeps the selected mode visible when effective config is env-overridden", async () => {
    const { buildSettingItems, mergeEffectiveConfigWithSelectedMode } = await import("./config-modal");
    const effectiveConfig = { ...DEFAULT_EXTENSION_CONFIG, mode: "yolo", debugLog: true };

    const modalConfig = mergeEffectiveConfigWithSelectedMode(effectiveConfig, "yolo-auto");

    expect(modalConfig).toMatchObject({ mode: "yolo-auto", debugLog: true });
    expect(buildSettingItems(modalConfig).find((item) => item.id === "mode"))
      .toMatchObject({ currentValue: "yolo-auto" });
  });

  it("applies mode changes without separate yolo flags", async () => {
    const modal = await import("./config-modal") as unknown as Record<string, unknown>;
    expect(typeof modal.applySetting).toBe("function");

    const applySetting = modal.applySetting as (config: unknown, id: string, value: string) => Record<string, unknown>;
    const next = applySetting({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" }, "mode", "yolo-auto");

    expect(next).toMatchObject({ mode: "yolo-auto" });
    expect(next).not.toHaveProperty("yoloMode");
    expect(next).not.toHaveProperty("yoloAutoMode");
  });

  it("removes classifier-level setting from settings list", async () => {
    const { buildSettingItems } = await import("./config-modal");
    expect(buildSettingItems(DEFAULT_EXTENSION_CONFIG).map((item) => item.id))
      .not.toContain("yoloAutoMaxLevel");
  });

  it("shows sandbox toggle only when sandbox state is provided", async () => {
    const { buildSettingItems } = await import("./config-modal");
    expect(buildSettingItems(DEFAULT_EXTENSION_CONFIG).map((item) => item.id)).not.toContain("sandbox");
    const sandbox = buildSettingItems(DEFAULT_EXTENSION_CONFIG, false).find((item) => item.id === "sandbox");
    expect(sandbox).toMatchObject({ currentValue: "off", values: ["on", "off"] });
  });
});
