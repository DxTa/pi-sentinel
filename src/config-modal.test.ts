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
    );

    expect(formatted.split("\n")).toEqual([
      "Mode chain (top wins): ▶ session auto · env – · project – · project (legacy) unreadable · " +
        "global manual · global (legacy) legacy flags: yoloMode=false · default manual",
      "Mode saves to session: memory only (lost on exit)",
      "Other settings save to global: /home/tester/.pi/agent/permissions.json",
    ]);
  });

  it("saves to the project's legacy fallback file when that layer supplies the mode", async () => {
    const { formatModeChain, formatModeSaveNotice } = await import("./config-modal");
    const legacyPath = "/workspace/.pi/agent/permissions.json";
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", path: "/workspace/.pi/permissions.json", savePath: legacyPath },
        { id: "project-config-legacy", name: "project (legacy)", mode: "yolo", path: legacyPath },
        { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
      ],
      effective: "yolo",
      source: "project-config-legacy",
    } as const;

    const formatted = formatModeChain(modeLayers);
    expect(formatted).toContain("project – · ▶ project (legacy) yolo");
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
    }, 50, "/workspace");

    expect(formatted).toContain("yoloAutoMode=true");
    expect(formatted).toContain("Mode saves to project: ./.pi/permissions.json");
    expect(formatted.replace(/\s/g, "")).toContain(globalPath);
    expect(formatted.split("\n").every((line) => visibleWidth(line) <= 50)).toBe(true);
  });
});

describe("mode save scope", () => {
  const layers = (source: string) => ({ layers: [], effective: "auto", source }) as never;

  it("saves to the scope that supplies the current mode", async () => {
    const { modeSaveScope } = await import("./config-modal");
    expect(modeSaveScope(layers("session"))).toBe("session");
    expect(modeSaveScope(layers("project"))).toBe("project");
    expect(modeSaveScope(layers("project-config-legacy"))).toBe("project");
    expect(modeSaveScope(layers("project-policy-legacy"))).toBe("project");
    expect(modeSaveScope(layers("global"))).toBe("global");
    expect(modeSaveScope(layers("global-policy-legacy"))).toBe("global");
  });

  it("uses the session above PI_SENTINEL_MODE and global for bundled defaults", async () => {
    const { formatModeChain, modeSaveScope } = await import("./config-modal");
    expect(modeSaveScope(layers("environment"))).toBe("session");
    expect(modeSaveScope(layers("bundled"))).toBe("global");
    expect(formatModeChain({
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", mode: "yolo", path: "PI_SENTINEL_MODE" },
      ],
      effective: "yolo",
      source: "environment",
    })).toContain("Mode saves to session: memory only, above PI_SENTINEL_MODE (lost on exit)");
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


  it("shows the effective mode and the layer that sets it", async () => {
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

    expect(buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, modeLayers)
      .find((item) => item.id === "mode"))
      .toMatchObject({ currentValue: "manual (env)" });
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

    const items = buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, modeLayers);
    expect(items.find((item) => item.id === "mode"))
      .toMatchObject({ currentValue: "yolo (project)", values: ["auto", "manual", "yolo"] });
    expect(items.map((item) => item.id)).not.toContain("modeScope");
  });

  it("tags toggles with their source and flags project overrides", async () => {
    const { buildSettingItems } = await import("./config-modal");
    const items = buildSettingItems(
      { ...DEFAULT_EXTENSION_CONFIG, debugLog: true },
      false,
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

describe("mode changes in the settings modal", () => {
  const DOWN = "\x1b[B";

  const modeLayersFrom = (source: "project" | "global" | "environment") => ({
    layers: [
      { id: "session", name: "session", path: "memory" },
      { id: "environment", name: "env", ...(source === "environment" ? { mode: "manual" } : {}), path: "PI_SENTINEL_MODE" },
      { id: "project", name: "project", ...(source === "project" ? { mode: "manual" } : {}), path: "/workspace/.pi/permissions.json" },
      { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
    ],
    effective: "manual",
    source,
  }) as const;

  async function openModal(controller: Record<string, unknown>, keys: string[]) {
    const { registerPermissionSystemCommand } = await import("./config-modal");
    const handlers = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> }>();
    registerPermissionSystemCommand(
      { registerCommand: (name: string, command: never) => handlers.set(name, command) } as never,
      { getConfig: () => ({ ...DEFAULT_EXTENSION_CONFIG, mode: "manual" }), getConfigPath: () => "", ...controller } as never,
    );
    const rendered: string[] = [];
    const ctx = {
      hasUI: true,
      cwd: "/workspace",
      ui: {
        notify: vi.fn(),
        custom: async (factory: (...args: unknown[]) => { render(width: number): string[]; handleInput(data: string): void }) => {
          const modal = factory({ requestRender: vi.fn() }, {}, {}, () => undefined);
          rendered.push(modal.render(82).join("\n"));
          for (const key of keys) modal.handleInput(key);
          rendered.push(modal.render(82).join("\n"));
        },
      },
    };
    await handlers.get("sentinel")?.handler("", ctx);
    return { ctx, rendered };
  }

  it("has no separate save-scope row", async () => {
    const { buildSettingItems } = await import("./config-modal");
    expect(buildSettingItems(DEFAULT_EXTENSION_CONFIG).map((item) => item.id))
      .toEqual(["mode", "permissionReviewLog", "debugLog"]);
  });

  it.each([
    ["project", "project", "Mode saves to project: ./.pi/permissions.json"],
    ["global", "global", "Mode saves to global: /home/tester/.pi/agent/permissions.json"],
    ["environment", "session", "Mode saves to session: memory only, above PI_SENTINEL_MODE (lost on exit)"],
  ] as const)("saves a mode change from %s to the %s scope", async (source, scope, header) => {
    const setConfig = vi.fn(() => true);
    const { ctx, rendered } = await openModal(
      { setConfig, getModeLayers: () => modeLayersFrom(source) },
      [" "], // Mode is the first row: manual -> yolo
    );

    expect(rendered[0]).toContain(header);
    expect(setConfig).toHaveBeenCalledWith(expect.objectContaining({ mode: "yolo" }), ctx, true, scope);
  });

  it("saves to global when no mode layers are available", async () => {
    const setConfig = vi.fn(() => true);
    const { ctx } = await openModal({ setConfig }, [" "]);
    expect(setConfig).toHaveBeenCalledWith(expect.objectContaining({ mode: "yolo" }), ctx, true, "global");
  });

  it("does not save the mode when a toggle changes", async () => {
    const setConfig = vi.fn(() => true);
    const { ctx } = await openModal(
      { setConfig, getModeLayers: () => modeLayersFrom("project") },
      [DOWN, DOWN, " "], // mode -> review log -> debug log, toggle
    );
    expect(setConfig).toHaveBeenCalledWith(expect.objectContaining({ debugLog: true }), ctx, false, "project");
  });
});

describe("/sentinel mode", () => {
  async function run(args: string, source: "project" | "global" = "global") {
    const { registerPermissionSystemCommand } = await import("./config-modal");
    const handlers = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> }>();
    const setConfig = vi.fn(() => true);
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "project", name: "project", ...(source === "project" ? { mode: "manual" } : {}), path: "/workspace/.pi/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/home/tester/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source,
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
    const ctx = { hasUI: false, cwd: "/workspace", ui: { notify: vi.fn() } };
    await handlers.get("sentinel")?.handler(args, ctx);
    return { ctx, setConfig };
  }

  it("sets the mode in an explicit scope", async () => {
    const { ctx, setConfig } = await run("mode yolo project");
    expect(setConfig).toHaveBeenCalledWith(expect.objectContaining({ mode: "yolo" }), ctx, true, "project");
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringContaining("Saved mode 'yolo' → project"), expect.any(String));
  });

  it("defaults to the scope that supplies the current mode", async () => {
    const { ctx, setConfig } = await run("mode auto", "project");
    expect(setConfig).toHaveBeenCalledWith(expect.objectContaining({ mode: "auto" }), ctx, true, "project");
  });

  it.each(["mode", "mode turbo", "mode auto everywhere", "mode auto global extra"])(
    "rejects %j with usage",
    async (args) => {
      const { ctx, setConfig } = await run(args);
      expect(setConfig).not.toHaveBeenCalled();
      expect(ctx.ui.notify).toHaveBeenCalledWith(
        "Usage: /sentinel mode <manual|yolo|auto> [session|project|global]",
        "warning",
      );
    },
  );
});

describe("long mode chain", () => {
  const DOWN = "\x1b[B";

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

    const labels = ["Bash sandbox", "Mode", "Permission review log", "Debug logging"];
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
    for (let row = 0; row < 4; row++) {
      modal?.handleInput(DOWN);
      expectUsable(18);
    }

    terminal.rows = 12;
    expectUsable(12);
    terminal.rows = 30;
    const tall = expectUsable(30);
    expect(tall.replace(/\s+/g, " ")).toContain("▶ global manual");
    expect(tall.replace(/\s+/g, " ")).toMatch(/Saves (to global|where the current mode is set)\./);
    modal?.handleInput("\x1b");
    expect(done).toHaveBeenCalledOnce();
    expect(setConfig).not.toHaveBeenCalled();
  });

});
