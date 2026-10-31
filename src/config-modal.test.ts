import { visibleWidth } from "@earendil-works/pi-tui";
import { describe, expect, it, vi } from "vitest";

import { DEFAULT_EXTENSION_CONFIG } from "./extension-config";

vi.mock("@earendil-works/pi-coding-agent", () => ({
  getSettingsListTheme: () => ({
    label: (text: string) => text,
    value: (text: string) => text,
    description: (text: string) => text,
    cursor: ">",
    hint: (text: string) => text,
  }),
}));


describe("mode chain formatting", () => {
  it("lists every layer on one line, marks the winner, and names both save targets", async () => {
    const { formatModeChain } = await import("./config-modal");
    const formatted = formatModeChain(
      {
        layers: [
          { id: "session", name: "session", mode: "auto", path: "memory" },
          { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
          { id: "project", name: "project", path: "/workspace/.pi/permissions.json" },
          {
            id: "project-config-legacy",
            name: "project (legacy)",
            path: "/workspace/.pi/agent/permissions.json",
            error: "unreadable",
          },
          { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
          {
            id: "global-policy-legacy",
            name: "global (legacy)",
            legacyMode: { yoloMode: false },
            path: "/home/tester/.pi/agent/pi-permissions.jsonc",
          },
          { id: "bundled", name: "bundled", mode: "manual", path: "/extension/config.json" },
        ],
        effective: "auto",
        source: "session",
      },
      "project",
    );

    expect(formatted.split("\n")).toEqual([
      "Mode chain (top wins): ▶ session auto · env – · project – · project (legacy) unreadable · " +
        "global manual · global (legacy) legacy flags: yoloMode=false · default manual",
      "Mode saves to project: /workspace/.pi/permissions.json",
      "Other settings save to global: /home/tester/.pi/agent/permissions.json",
    ]);
  });

  it("uses the project's legacy save fallback as the mode save target", async () => {
    const { formatModeChain, formatModeSaveNotice } = await import("./config-modal");
    const legacyPath = "/workspace/.pi/agent/permissions.json";
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", mode: "manual", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", path: "/workspace/.pi/permissions.json", savePath: legacyPath },
        { id: "project-config-legacy", name: "project (legacy)", mode: "yolo", path: legacyPath },
        { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "environment",
    } as const;

    const formatted = formatModeChain(modeLayers, "project");
    expect(formatted).toContain("▶ env manual · project – · project (legacy) yolo");
    expect(formatted).toContain("Mode saves to project: " + legacyPath);
    expect(formatModeSaveNotice("manual", "project", modeLayers)).toContain(
      "project (" + legacyPath + ")",
    );
  });

  it("wraps within narrow widths and shortens project paths", async () => {
    const { formatModeChain } = await import("./config-modal");
    const globalPath = "/Users/bob/.pi/agent/permissions.json";
    const formatted = formatModeChain({
      layers: [
        {
          id: "project-extension-legacy",
          name: "project extension (legacy)",
          legacyMode: { yoloAutoMode: true },
          path: "/workspace/.pi/agent/pi-sentinel.json",
        },
        { id: "project", name: "project", path: "/workspace/.pi/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: globalPath },
      ],
      effective: "auto",
      source: "project-extension-legacy",
    }, "project", 50, "/workspace");

    expect(formatted).toContain("yoloAutoMode=true");
    expect(formatted).toContain("Mode saves to project: ./.pi/permissions.json");
    expect(formatted.replace(/\s/g, "")).toContain(globalPath);
    expect(formatted.split("\n").every((line) => visibleWidth(line) <= 50)).toBe(true);
  });
});

describe("mode source", () => {
  const modeLayers = {
    layers: [
      { id: "session", name: "session", path: "memory" },
      { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
      { id: "project", name: "project", mode: "manual", path: "/workspace/.pi/permissions.json" },
      { id: "global", name: "global", mode: "auto", path: "/home/tester/.pi/agent/permissions.json" },
      { id: "bundled", name: "bundled", mode: "auto", path: "/extension/config.json" },
    ],
    effective: "manual",
    source: "project",
  } as const;

  it("names the source when it is the selected scope", async () => {
    const { describeModeSource } = await import("./config-modal");
    expect(describeModeSource(modeLayers, "project")).toBe("project");
  });

  it("says what a higher layer overrides in the selected scope", async () => {
    const { describeModeSource } = await import("./config-modal");
    expect(describeModeSource(modeLayers, "global")).toBe("from project, overrides global: auto");
    expect(describeModeSource({
      ...modeLayers,
      layers: modeLayers.layers.map((layer) => layer.id === "global" ? { ...layer, mode: undefined } : layer),
    }, "global")).toBe("from project; global unset");
  });

  it("marks an unset higher scope as inherited", async () => {
    const { describeModeSource } = await import("./config-modal");
    expect(describeModeSource(modeLayers, "session")).toBe("inherited from project");
  });
});

describe("mode save notice", () => {
  it("names the save destination, effective source, and shadowing layer", async () => {
    const modal = await import("./config-modal") as unknown as {
      formatModeSaveNotice: (mode: string, scope: string, layers: unknown) => string;
    };
    const layers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", mode: "manual", path: "/workspace/.pi/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "project",
    };

    expect(modal.formatModeSaveNotice("yolo", "global", layers)).toBe(
      "Saved mode 'yolo' → global (/home/tester/.pi/agent/permissions.json). " +
        "Effective: manual (from project, which overrides the saved global value).",
    );
    expect(modal.formatModeSaveNotice("yolo", "session", {
      ...layers,
      effective: "yolo",
      source: "session",
    })).toBe(
      "Saved mode 'yolo' → session (memory only; lost on exit). Effective: yolo (from session).",
    );
  });
});

describe("permission mode settings", () => {
  it("offers one mode selector with manual, yolo, and auto", async () => {
    const modal = await import("./config-modal") as unknown as Record<string, unknown>;
    expect(typeof modal.buildSettingItems).toBe("function");

    const buildSettingItems = modal.buildSettingItems as (config: unknown) => Array<Record<string, unknown>>;
    const [mode] = buildSettingItems({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" });

    expect(mode).toMatchObject({
      id: "mode",
      label: "Mode",
      currentValue: "manual",
      values: ["manual", "yolo", "auto"],
    });
  });


  it("compares the effective mode with the project's save fallback", async () => {
    const { buildSettingItems } = await import("./config-modal");
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", mode: "manual", path: "PI_SENTINEL_MODE" },
        {
          id: "project", name: "project",
          path: "/workspace/.pi/permissions.json",
          savePath: "/workspace/.pi/agent/permissions.json",
        },
        { id: "project-config-legacy", name: "project (legacy)", mode: "yolo", path: "/workspace/.pi/agent/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "environment",
    } as const;

    expect(buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, "project", modeLayers)
      .find((item) => item.id === "mode"))
      .toMatchObject({ currentValue: "manual (from env, overrides project (legacy): yolo)" });
  });

  it("keeps the selected mode visible when effective config is env-overridden", async () => {
    const { buildSettingItems, mergeEffectiveConfigWithSelectedMode } = await import("./config-modal");
    const effectiveConfig = { ...DEFAULT_EXTENSION_CONFIG, mode: "yolo", debugLog: true };

    const modalConfig = mergeEffectiveConfigWithSelectedMode(effectiveConfig, "auto");

    expect(modalConfig).toMatchObject({ mode: "auto", debugLog: true });
    expect(buildSettingItems(modalConfig).find((item) => item.id === "mode"))
      .toMatchObject({ currentValue: "auto" });
  });

  it("applies mode changes without separate yolo flags", async () => {
    const modal = await import("./config-modal") as unknown as Record<string, unknown>;
    expect(typeof modal.applySetting).toBe("function");

    const applySetting = modal.applySetting as (config: unknown, id: string, value: string) => Record<string, unknown>;
    const next = applySetting({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" }, "mode", "auto");

    expect(next).toMatchObject({ mode: "auto" });
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


describe("per-row provenance", () => {
  it("shows the effective mode with its source and cycles from the effective value", async () => {
    const { buildSettingItems } = await import("./config-modal");
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", mode: "yolo", path: "/workspace/.pi/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
      ],
      effective: "yolo",
      source: "project",
    } as const;

    const projectMode = buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, "project", modeLayers)
      .find((item) => item.id === "mode");
    expect(projectMode).toMatchObject({ currentValue: "yolo (project)", values: ["auto", "manual", "yolo"] });

    const items = buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, "session", modeLayers);
    expect(items.find((item) => item.id === "mode")).toMatchObject({ currentValue: "yolo (inherited from project)" });
    expect(items.find((item) => item.id === "modeScope")).toMatchObject({ label: "Save mode to" });
  });

  it("tags toggles with their source and flags project overrides", async () => {
    const { buildSettingItems } = await import("./config-modal");
    const items = buildSettingItems(
      { ...DEFAULT_EXTENSION_CONFIG, debugLog: true },
      false,
      "global",
      undefined,
      { sandbox: "global", permissionReviewLog: "default", debugLog: "project" },
    );

    expect(items.find((item) => item.id === "sandbox")).toMatchObject({
      currentValue: "off (global)",
      values: ["on", "off"],
    });
    expect(items.find((item) => item.id === "permissionReviewLog")).toMatchObject({
      currentValue: "on (default)",
      values: ["off", "on"],
    });
    expect(items.find((item) => item.id === "debugLog")).toMatchObject({
      currentValue: "on (project, overrides global)",
    });
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
          const list = factory({ requestRender: vi.fn() }, {}, {}, () => undefined);
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

  it("updates the save target and inherited Mode value before saving", async () => {
    const { registerPermissionSystemCommand } = await import("./config-modal");
    const handlers = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> }>();
    const setConfig = vi.fn(() => true);
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", path: "/workspace/.pi/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "global",
    } as const;
    registerPermissionSystemCommand(
      { registerCommand: (name: string, command: never) => handlers.set(name, command) } as never,
      {
        getConfig: () => ({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" }),
        setConfig,
        getConfigPath: () => "",
        getModeLayers: () => modeLayers,
      } as never,
    );

    let beforeScopeChange = "";
    let afterScopeChange = "";
    const ctx = {
      hasUI: true,
      cwd: "/workspace",
      ui: {
        notify: vi.fn(),
        custom: async (factory: (...args: unknown[]) => {
          render(width: number): string[];
          handleInput(data: string): void;
        }) => {
          const component = factory({ requestRender: vi.fn() }, {}, {}, () => undefined);
          beforeScopeChange = component.render(82).join("\n");
          component.handleInput(DOWN);
          component.handleInput(" ");
          afterScopeChange = component.render(82).join("\n");
          expect(setConfig).not.toHaveBeenCalled();
          component.handleInput(UP);
          component.handleInput(" ");
        },
      },
    };

    await handlers.get("sentinel")?.handler("", ctx);

    expect(beforeScopeChange).toContain("▶ global manual");
    expect(beforeScopeChange).toContain("Mode saves to global: /home/tester/.pi/agent/permissions.json");
    expect(beforeScopeChange).toContain("manual (global)");
    expect(afterScopeChange).toContain("Mode saves to session: memory only (lost on exit)");
    expect(afterScopeChange).toContain("Save mode to");
    expect(afterScopeChange).toContain("manual (inherited from global)");
    expect(setConfig).toHaveBeenCalledWith(
      expect.objectContaining({ mode: "yolo" }),
      ctx,
      true,
      "session",
    );
  });

  it.each([82, 50])("keeps controls and save targets visible with a long chain at %i×18", async (width) => {
    const { registerPermissionSystemCommand } = await import("./config-modal");
    const handlers = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> }>();
    const longRoot = "/Users/bob/dev/pi-sentinel/workspaces/a-very-long-project-name/.pi";
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", path: longRoot + "/permissions.json" },
        { id: "project-policy-legacy", name: "project policy (legacy)", mode: "manual", path: longRoot + "/agent/pi-permissions.jsonc" },
        { id: "project-extension-legacy", name: "project extension (legacy)", mode: "yolo", path: longRoot + "/agent/pi-sentinel.json" },
        { id: "project-config-legacy", name: "project config (legacy)", mode: "auto", path: longRoot + "/agent/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/Users/bob/.pi/agent/permissions.json" },
        { id: "global-policy-legacy", name: "global (legacy)", path: "/Users/bob/.pi/agent/pi-permissions.jsonc" },
        { id: "bundled", name: "bundled", mode: "auto", path: "/Users/bob/dev/pi-sentinel/config.json" },
      ],
      effective: "manual",
      source: "global",
    } as const;
    const setConfig = vi.fn(() => true);
    const done = vi.fn();
    registerPermissionSystemCommand(
      { registerCommand: (name: string, command: never) => handlers.set(name, command) } as never,
      {
        getConfig: () => ({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" }),
        setConfig,
        getConfigPath: () => "",
        getModeLayers: () => modeLayers,
        getSandboxEnabled: () => true,
        getSettingSources: () => ({ sandbox: "global", permissionReviewLog: "default", debugLog: "default" }),
      } as never,
    );

    let modal: { render(width: number): string[]; handleInput(data: string): void } | undefined;
    let maximumHeight: string | undefined;
    const terminal = { rows: 18 };
    const ctx = {
      hasUI: true,
      cwd: "/Users/bob/dev/pi-sentinel/workspaces/a-very-long-project-name",
      ui: {
        notify: vi.fn(),
        custom: async (
          factory: (...args: unknown[]) => { render(width: number): string[]; handleInput(data: string): void },
          options: unknown,
        ) => {
          modal = factory({ terminal, requestRender: vi.fn() }, {}, {}, done);
          maximumHeight = (options as { overlayOptions: { maxHeight: string } }).overlayOptions.maxHeight;
        },
      },
    };

    await handlers.get("sentinel")?.handler("", ctx);
    expect(maximumHeight).toBe("100%");

    const labels = ["Bash sandbox", "Mode", "Save mode to", "Permission review log", "Debug logging"];
    const expectUsable = (rows: number): string => {
      const lines = modal?.render(width) ?? [];
      expect(lines.length).toBeLessThanOrEqual(rows);
      expect(lines.every((line) => visibleWidth(line) <= width)).toBe(true);
      const rendered = lines.join("\n");
      for (const label of labels) expect(rendered).toContain(label);
      expect(rendered).toContain("Enter/Space to change");
      return rendered;
    };

    const initial = expectUsable(18);
    expect(initial).toContain("Mode saves to global:");
    expect(initial).toContain("Other settings save to global:");
    expect(initial).toContain("manual (global)");
    expect(initial).toContain("on (global)");

    // Moving the cursor shows longer descriptions; they must not clip controls.
    for (let row = 0; row < 5; row++) {
      modal?.handleInput(DOWN);
      expectUsable(18);
    }
    modal?.handleInput(DOWN); // sandbox -> mode
    modal?.handleInput(DOWN); // mode -> scope
    modal?.handleInput(" "); // global -> session
    const session = expectUsable(18);
    expect(session).toContain("memory only (lost on exit)");
    // Narrow terminals truncate long values; the source prefix stays readable.
    expect(session).toContain(width >= 82 ? "manual (inherited from global)" : "manual (inherited");

    terminal.rows = 12;
    expectUsable(12);
    terminal.rows = 30;
    const tall = expectUsable(30);
    expect(tall.replace(/\s+/g, " ")).toContain("▶ global manual");
    expect(tall).toContain("Where the next mode change");
    modal?.handleInput("\x1b");
    expect(done).toHaveBeenCalledOnce();
    expect(setConfig).not.toHaveBeenCalled();
  });

});
