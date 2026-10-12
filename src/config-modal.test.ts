import { describe, expect, it, vi } from "vitest";

import { DEFAULT_EXTENSION_CONFIG } from "./extension-config";

vi.mock("@earendil-works/pi-coding-agent", () => ({ getSettingsListTheme: () => ({}) }));

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

describe("mode scope selector", () => {
  const DOWN = "\x1b[B";
  const UP = "\x1b[A";

  it("lists a scope row right after mode, defaulting to global", async () => {
    const { buildSettingItems } = await import("./config-modal");
    const items = buildSettingItems(DEFAULT_EXTENSION_CONFIG);

    expect(items[1]).toMatchObject({
      id: "modeScope",
      currentValue: "global",
      values: ["session", "project", "global"],
    });
  });

  it("passes the chosen scope to setConfig when the mode changes", async () => {
    const { registerPermissionSystemCommand } = await import("./config-modal");
    const handlers = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> }>();
    const setConfig = vi.fn(() => true);
    registerPermissionSystemCommand(
      { registerCommand: (name: string, command: never) => handlers.set(name, command) } as never,
      {
        getConfig: () => ({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" }),
        setConfig,
        getConfigPath: () => "",
      },
    );
    const ctx = {
      hasUI: true,
      ui: {
        notify: vi.fn(),
        custom: async (factory: (...args: unknown[]) => { handleInput(data: string): void }) => {
          const list = factory({}, {}, {}, () => undefined);
          list.handleInput(DOWN); // select scope row
          list.handleInput(" "); // global -> session
          list.handleInput(UP); // select mode row
          list.handleInput(" "); // manual -> yolo
        },
      },
    };

    await handlers.get("sentinel")?.handler("", ctx);

    expect(setConfig).toHaveBeenCalledTimes(1);
    expect(setConfig).toHaveBeenCalledWith(
      expect.objectContaining({ mode: "yolo" }),
      ctx,
      true,
      "session",
    );
  });
});
