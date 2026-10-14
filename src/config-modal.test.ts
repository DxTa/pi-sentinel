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
  it("shows the selected scope, unset values, effective mode, and write targets", async () => {
    const { formatModeChain } = await import("./config-modal");
    const formatted = formatModeChain(
      {
        layers: [
          { id: "session", name: "session", mode: "yolo-auto", path: "memory" },
          { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
          { id: "project", name: "project", path: "/workspace/.pi/permissions.json" },
          {
            id: "project-config-legacy",
            name: "project (legacy)",
            path: "/workspace/.pi/agent/permissions.json",
            error: "unreadable",
          },
          { id: "global", name: "global", mode: "manual", path: "/home/user/.pi/agent/permissions.json" },
          {
            id: "global-policy-legacy",
            name: "global (legacy)",
            legacyMode: { yoloMode: false },
            path: "/home/user/.pi/agent/pi-permissions.jsonc",
          },
          { id: "bundled", name: "bundled", mode: "manual", path: "/extension/config.json" },
        ],
        effective: "yolo-auto",
        source: "session",
      },
      "project",
    );

    expect(formatted.split("\n")).toEqual([
      "Mode chain (top wins):",
      "  session yolo-auto (memory)",
      "  env — not set (PI_SENTINEL_MODE)",
      "  project — not set (/workspace/.pi/permissions.json) ← selected",
      "  project (legacy) — unreadable (/workspace/.pi/agent/permissions.json)",
      "  global manual (/home/user/.pi/agent/permissions.json)",
      "  global (legacy) legacy flags: yoloMode=false (/home/user/.pi/agent/pi-permissions.jsonc)",
      "  bundled manual (/extension/config.json)",
      "Effective this session: yolo-auto (from session)",
      "Saving Mode writes: /workspace/.pi/permissions.json",
      "Logs & sandbox always write: /home/user/.pi/agent/permissions.json",
    ]);
  });

  it("marks the project fallback row and save path", async () => {
    const { formatModeChain, formatModeSaveNotice } = await import("./config-modal");
    const legacyPath = "/workspace/.pi/agent/permissions.json";
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", mode: "manual", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", path: "/workspace/.pi/permissions.json", savePath: legacyPath },
        { id: "project-config-legacy", name: "project (legacy)", mode: "yolo", path: legacyPath },
        { id: "global", name: "global", mode: "manual", path: "/home/user/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "environment",
    } as const;

    const formatted = formatModeChain(modeLayers, "project");
    expect(formatted).toContain("project (legacy) yolo (" + legacyPath + ") ← selected");
    expect(formatted).toContain("Saving Mode writes: " + legacyPath);
    expect(formatModeSaveNotice("manual", "project", modeLayers)).toContain(
      "project (" + legacyPath + ")",
    );
  });

  it("keeps effective provenance and the selected marker at narrow widths", async () => {
    const { formatModeChain } = await import("./config-modal");
    const formatted = formatModeChain(
      {
        layers: [
          { id: "session", name: "session", path: "memory" },
          { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
          {
            id: "global",
            name: "global",
            mode: "manual",
            path: "/Users/bob/.pi/agent/permissions.json",
          },
        ],
        effective: "yolo-auto",
        source: "environment",
      },
      "global",
      50,
      "/workspace",
    );
    const lines = formatted.split("\n");

    expect(lines).toContain("Effective this session: yolo-auto (from env)");
    expect(lines.some((line) => line.includes("← selected"))).toBe(true);
    expect(lines.every((line) => visibleWidth(line) <= 50)).toBe(true);
  });

  it("keeps a long legacy source and all flag details instead of truncating metadata", async () => {
    const { formatModeChain } = await import("./config-modal");
    const formatted = formatModeChain({
      layers: [
        {
          id: "project-extension-legacy",
          name: "project extension (legacy)",
          legacyMode: { yoloAutoMode: true },
          path: "/workspace/.pi/agent/pi-sentinel.json",
        },
        { id: "global", name: "global", path: "/home/user/.pi/agent/permissions.json" },
      ],
      effective: "yolo-auto",
      source: "project-extension-legacy",
    }, "global", 50, "/workspace");

    expect(formatted).toContain("Effective: yolo-auto ← project extension (legacy)");
    expect(formatted).toContain("yoloAutoMode=true");
    expect(formatted).toContain("./.pi/agent/pi-sentinel.json");
    expect(formatted).toContain("← selected");
    expect(formatted.split("\n").every((line) => visibleWidth(line) <= 50)).toBe(true);
  });

  it("keeps both save destinations complete at 50 columns", async () => {
    const { formatModeChain } = await import("./config-modal");
    const globalPath = "/Users/bob/.pi/agent/permissions.json";
    const formatted = formatModeChain({
      layers: [{ id: "global", name: "global", mode: "manual", path: globalPath }],
      effective: "manual",
      source: "global",
    }, "global", 50);
    const destinations = formatted.slice(formatted.indexOf("Saving Mode writes:"));

    const [modeDestination, logsDestination] = destinations.split("Logs & sandbox always write:");
    expect(modeDestination.replace(/\s/g, "")).toContain(globalPath);
    expect(logsDestination.replace(/\s/g, "")).toBe(globalPath);
    expect(formatted.split("\n").every((line) => visibleWidth(line) <= 50)).toBe(true);
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
        { id: "global", name: "global", mode: "manual", path: "/home/user/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "project",
    };

    expect(modal.formatModeSaveNotice("yolo", "global", layers)).toBe(
      "Saved mode 'yolo' → global (/home/user/.pi/agent/permissions.json). " +
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


  it("shows the configured value from the project's save fallback", async () => {
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
        { id: "global", name: "global", mode: "manual", path: "/home/user/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "environment",
    } as const;

    expect(buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, "project", modeLayers)
      .find((item) => item.id === "mode")).toMatchObject({ currentValue: "yolo" });
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


describe("scope-specific mode value", () => {
  it("shows the saved value or inherited effective mode for the selected scope", async () => {
    const { buildSettingItems } = await import("./config-modal");
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", mode: "yolo", path: "/workspace/.pi/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/home/user/.pi/agent/permissions.json" },
      ],
      effective: "manual",
      source: "global",
    } as const;

    const selectedItems = buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, "project", modeLayers);
    expect(selectedItems.find((item) => item.id === "mode")).toMatchObject({ currentValue: "yolo" });
    expect(selectedItems.find((item) => item.id === "modeScope")).toMatchObject({
      label: "Mode saves to",
    });

    const inheritedItems = buildSettingItems(DEFAULT_EXTENSION_CONFIG, undefined, "session", modeLayers);
    const inheritedMode = inheritedItems.find((item) => item.id === "mode");
    expect(inheritedMode).toMatchObject({ currentValue: "inherits: manual" });
    expect(inheritedMode?.values).toEqual(["yolo", "yolo-auto", "manual"]);
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

  it("updates the chain and inherited Mode value before saving", async () => {
    const { registerPermissionSystemCommand } = await import("./config-modal");
    const handlers = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> }>();
    const setConfig = vi.fn(() => true);
    const modeLayers = {
      layers: [
        { id: "session", name: "session", path: "memory" },
        { id: "environment", name: "env", path: "PI_SENTINEL_MODE" },
        { id: "project", name: "project", path: "/workspace/.pi/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/home/user/.pi/agent/permissions.json" },
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

    expect(beforeScopeChange).toContain("global manual (/home/user/.pi/agent/permissions.json) ← selected");
    expect(beforeScopeChange).toContain("Saving Mode writes: /home/user/.pi/agent/permissions.json");
    expect(afterScopeChange).toContain("session — not set (memory) ← selected");
    expect(afterScopeChange).toContain("Mode saves to");
    expect(afterScopeChange).toContain("inherits: manual");
    expect(afterScopeChange).toContain("Saving Mode writes: memory only (lost on exit)");
    expect(setConfig).toHaveBeenCalledWith(
      expect.objectContaining({ mode: "yolo" }),
      ctx,
      true,
      "session",
    );
  });

  it.each([82, 50])("keeps controls and provenance visible while paging a long chain at %i×18", async (width) => {
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
        { id: "project-config-legacy", name: "project config (legacy)", mode: "yolo-auto", path: longRoot + "/agent/permissions.json" },
        { id: "global", name: "global", mode: "manual", path: "/Users/bob/.pi/agent/permissions.json" },
        { id: "global-policy-legacy", name: "global (legacy)", path: "/Users/bob/.pi/agent/pi-permissions.jsonc" },
        { id: "bundled", name: "bundled", mode: "yolo-auto", path: "/Users/bob/dev/pi-sentinel/config.json" },
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
      } as never,
    );

    let visibleLines: string[] = [];
    let renderedLineCount = 0;
    let maximumHeight: string | undefined;
    let modal: { render(width: number): string[]; handleInput(data: string): void } | undefined;
    const terminal = { rows: 18 };
    const ctx = {
      hasUI: true,
      cwd: "/Users/bob/dev/pi-sentinel/workspaces/a-very-long-project-name",
      ui: {
        notify: vi.fn(),
        custom: async (
          factory: (...args: unknown[]) => {
            render(width: number): string[];
            handleInput(data: string): void;
          },
          options: unknown,
        ) => {
          modal = factory({ terminal, requestRender: vi.fn() }, {}, {}, done);
          const overlayOptions = (options as { overlayOptions: { maxHeight: string } }).overlayOptions;
          maximumHeight = overlayOptions.maxHeight;
          visibleLines = modal.render(width);
          renderedLineCount = visibleLines.length;
        },
      },
    };

    await handlers.get("sentinel")?.handler("", ctx);

    expect(maximumHeight).toBe("100%");
    expect(renderedLineCount).toBeLessThanOrEqual(18);
    expect(visibleLines.join("\n")).toContain("Bash sandbox");
    expect(visibleLines.join("\n")).toContain("Permission review log");
    expect(visibleLines.join("\n")).toContain("Saving Mode writes:");
    expect(visibleLines.join("\n")).toContain("Logs & sandbox");
    const destinations = visibleLines.join("\n").split("Saving Mode writes:")[1]
      .split("Bash sandbox")[0].split("Logs & sandbox always write:");
    expect(destinations).toHaveLength(2);
    for (const destination of destinations) {
      expect(destination.replace(/\s/g, "")).toContain("/Users/bob/.pi/agent/permissions.json");
    }
    expect(visibleLines.join("\n")).toContain("Mode saves to");
    expect(visibleLines.join("\n")).toContain("Debug logging");
    expect(visibleLines.join("\n")).toContain("Effective this session: manual (from global)");

    expect(visibleLines.join("\n")).toContain("Selected: global ← selected");
    expect(visibleLines.join("\n")).toContain("PgUp/PgDn");
    expect(visibleLines.every((line) => visibleWidth(line) <= width)).toBe(true);

    const pages = [visibleLines.join("\n")];
    for (;;) {
      modal?.handleInput("\x1b[6~");
      const lines = modal?.render(width) ?? [];
      expect(lines.length).toBeLessThanOrEqual(18);
      const rendered = lines.join("\n");
      expect(rendered).toContain("Selected: global ← selected");
      expect(rendered).toContain("Effective this session: manual (from global)");
      expect(rendered).toContain("Debug logging");
      expect(rendered).toContain("Permission review log");
      expect(lines.every((line) => visibleWidth(line) <= width)).toBe(true);
      if (rendered === pages.at(-1)) break;
      pages.push(rendered);
    }
    for (const layer of modeLayers.layers) expect(pages.join("\n")).toContain(layer.name);
    expect(pages.at(-1)).toContain("config.json");
    expect(pages.join("\n")).toContain("pi-sentinel.json");
    expect(pages.join("\n")).toContain("config.json");
    for (let page = 0; page < pages.length; page++) modal?.handleInput("\x1b[5~");
    expect(modal?.render(width).join("\n")).toBe(pages[0]);
    expect(setConfig).not.toHaveBeenCalled();

    // Moving the settings cursor must not make its longer descriptions clip controls.
    for (let row = 0; row < 5; row++) {
      modal?.handleInput(DOWN);
      const lines = modal?.render(width) ?? [];
      expect(lines.length).toBeLessThanOrEqual(18);
      const rendered = lines.join("\n");
      for (const label of ["Bash sandbox", "Mode saves to", "Permission review log", "Debug logging"])
        expect(rendered).toContain(label);
      expect(rendered).toContain("Effective this session: manual (from global)");
      expect(rendered).toContain("Enter/Space to change");
    }
    modal?.handleInput(DOWN); // sandbox -> mode
    modal?.handleInput(DOWN); // mode -> scope
    modal?.handleInput(" "); // global -> session
    const sessionLines = modal?.render(width) ?? [];
    expect(sessionLines.length).toBeLessThanOrEqual(18);
    expect(sessionLines.join("\n")).toContain("Selected: session ← selected");
    expect(sessionLines.join("\n")).toContain("memory only (lost on exit)");
    expect(sessionLines.join("\n")).toContain("inherits: manual");

    terminal.rows = 15;
    const shorterLines = modal?.render(width) ?? [];
    expect(shorterLines.length).toBeLessThanOrEqual(15);
    for (const label of ["Bash sandbox", "Mode saves to", "Permission review log", "Debug logging"])
      expect(shorterLines.join("\n")).toContain(label);
    expect(shorterLines.join("\n")).toContain("Selected: session ← selected");
    expect(shorterLines.join("\n")).toContain("Enter/Space to change");
    terminal.rows = 20;
    const tallerLines = modal?.render(width) ?? [];
    expect(tallerLines.length).toBeLessThanOrEqual(20);
    expect(tallerLines.join("\n")).toContain("Where the next mode change");
    modal?.handleInput("\x1b");
    expect(done).toHaveBeenCalledOnce();
    expect(setConfig).not.toHaveBeenCalled();
  });

});
