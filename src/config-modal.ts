import { homedir } from "node:os";
import { relative, sep } from "node:path";

import {
  type ExtensionAPI,
  type ExtensionCommandContext,
  getSettingsListTheme,
} from "@earendil-works/pi-coding-agent";
import {
  type SettingItem,
  SettingsList,
  Text,
  wrapTextWithAnsi,
} from "@earendil-works/pi-tui";

import {
  DEFAULT_EXTENSION_CONFIG,
  type ModeScope,
  PERMISSION_MODES,
  type PermissionMode,
  type PermissionSystemExtensionConfig,
} from "./extension-config";
import type { Ruleset } from "./rule";
import type { ModeLayer, ModeLayers } from "./runtime";
import type { SettingSource, SettingSources } from "./scoped-config";

interface PermissionSystemConfigController {
  getConfig(): PermissionSystemExtensionConfig;
  setConfig(
    next: PermissionSystemExtensionConfig,
    ctx: ExtensionCommandContext,
    modeWasExplicitlySelected: boolean,
    modeScope: ModeScope,
  ): boolean;
  resetConfig?(ctx: ExtensionCommandContext): void;
  getConfigPath(cwd?: string | null): string;
  getModeLayers?(cwd?: string | null): ModeLayers;
  /** Optional: returns the composed config-layer ruleset for origin display. */
  getComposedRules?(): Ruleset;
  /** Optional runtime state for model-backed auto worker diagnostics. */
  getAutoModeStatus?(): string;
  /** Optional: effective sandbox state and global toggle. */
  getSandboxEnabled?(): boolean;
  /** Optional: which config scope supplies each toggle, for per-row provenance. */
  getSettingSources?(cwd?: string | null): SettingSources | undefined;
  setSandboxEnabled?(enabled: boolean, ctx: ExtensionCommandContext): void;
}

const ON_OFF = ["on", "off"];
const MODES: PermissionMode[] = [...PERMISSION_MODES];
const MODE_SCOPES: ModeScope[] = ["session", "project", "global"];
const COMMAND_ARGUMENTS = [
  {
    value: "show",
    label: "Show active settings",
    description: "Display the current pi-sentinel config summary",
  },
  {
    value: "path",
    label: "Show config path",
    description: "Display bundled, global, and project permission paths",
  },
  {
    value: "reset",
    label: "Reset defaults",
    description: "Remove global yolo/logging overrides and use bundled defaults",
  },
  {
    value: "help",
    label: "Show help",
    description: "Display command usage",
  },
] as const;
const USAGE_TEXT =
  "Usage: /sentinel [show|path|reset|help] (or run /sentinel with no args to open settings modal)";

function cloneDefaultConfig(): PermissionSystemExtensionConfig {
  return {
    debugLog: DEFAULT_EXTENSION_CONFIG.debugLog,
    permissionReviewLog: DEFAULT_EXTENSION_CONFIG.permissionReviewLog,
    mode: DEFAULT_EXTENSION_CONFIG.mode,
    yoloAskBashPatterns: [...DEFAULT_EXTENSION_CONFIG.yoloAskBashPatterns],
  };
}

function toOnOff(value: boolean): string {
  return value ? "on" : "off";
}

function formatRulesSummary(rules: Ruleset): string {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- origin may be absent despite its type
  const configRules = rules.filter((r) => r.layer === "config" && r.origin);
  if (configRules.length === 0) return "";
  const formatted = configRules
    .map((r) => {
      const key =
        r.pattern === "*" ? r.surface : `${r.surface}["${r.pattern}"]`;
      return `${key}=${r.action} (${r.origin})`;
    })
    .join(", ");
  return `\n  rules: ${formatted}`;
}

function summarizeConfig(
  config: PermissionSystemExtensionConfig,
  rules?: Ruleset,
  autoModeStatus?: string,
): string {
  const knobs = [
    `mode=${config.mode}`,
    `permissionReviewLog=${toOnOff(config.permissionReviewLog)}`,
    `debugLog=${toOnOff(config.debugLog)}`,
  ].join(", ");
  const rulesSuffix = rules ? formatRulesSummary(rules) : "";
  const workerSuffix = autoModeStatus ? `, ${autoModeStatus}` : "";
  return `${knobs}${workerSuffix}${rulesSuffix}`;
}

/** User-facing layer name; the bundled config.json reads as "default". */
function layerLabel(layer: Pick<ModeLayer, "id" | "name">): string {
  return layer.id === "bundled" ? "default" : layer.name;
}

function describeLayerMode(layer: ModeLayer): string {
  if (layer.error) return "unreadable";
  const legacyFlags = formatLegacyModeFlags(layer);
  if (layer.mode !== undefined) return legacyFlags ? layer.mode + " (" + legacyFlags + ")" : layer.mode;
  return legacyFlags ? "legacy flags: " + legacyFlags : "unset";
}

/** Put the value after `current` first, so the first press moves to the next value. */
function rotateAfter<T>(values: readonly T[], current: T): T[] {
  const index = values.indexOf(current);
  return index < 0 ? [...values] : [...values.slice(index + 1), ...values.slice(0, index + 1)];
}

/**
 * Where the effective mode comes from, relative to the scope a change saves to:
 * - `project`: the selected scope is the source;
 * - `from project, overrides global: auto`: a higher layer hides the selected one;
 * - `inherited from global`: the selected scope is unset and a lower layer applies.
 */
export function describeModeSource(modeLayers: ModeLayers, selectedScope: ModeScope): string {
  const selectedLayer = getSelectedModeLayer(modeLayers, selectedScope);
  const sourceLayer = modeLayers.layers.find((layer) => layer.id === modeLayers.source);
  const sourceName = sourceLayer ? layerLabel(sourceLayer) : modeLayers.source;
  if (!selectedLayer || !sourceLayer || selectedLayer === sourceLayer) return sourceName;
  const selectedIndex = modeLayers.layers.indexOf(selectedLayer);
  const sourceIndex = modeLayers.layers.indexOf(sourceLayer);
  if (sourceIndex < selectedIndex) {
    const selectedValue = describeLayerMode(selectedLayer);
    return selectedValue === "unset"
      ? "from " + sourceName + "; " + layerLabel(selectedLayer) + " unset"
      : "from " + sourceName + ", overrides " + layerLabel(selectedLayer) + ": " + selectedValue;
  }
  return "inherited from " + sourceName;
}

/** Toggles always save to the global file, so a project value is flagged as an override. */
function describeToggleSource(source: SettingSource): string {
  return source === "project" ? "project, overrides global" : source;
}

function withSource(value: string, source: string | undefined): string {
  return source ? value + " (" + source + ")" : value;
}

function toggleItem(
  id: string,
  label: string,
  description: string,
  value: boolean,
  source: SettingSource | undefined,
): SettingItem {
  const raw = toOnOff(value);
  return {
    id,
    label,
    description,
    currentValue: withSource(raw, source && describeToggleSource(source)),
    values: source ? rotateAfter(ON_OFF, raw) : ON_OFF,
  };
}

export function buildSettingItems(
  config: PermissionSystemExtensionConfig,
  sandboxEnabled?: boolean,
  modeScope: ModeScope = "global",
  modeLayers?: ModeLayers,
  sources?: SettingSources,
): SettingItem[] {
  const modeValue = modeLayers
    ? withSource(modeLayers.effective, describeModeSource(modeLayers, modeScope))
    : config.mode;
  const modeValues = modeLayers ? rotateAfter(MODES, modeLayers.effective) : MODES;
  const sandboxItem: SettingItem[] = sandboxEnabled === undefined ? [] : [toggleItem(
    "sandbox",
    "Bash sandbox",
    "Run Bash in SRT sandbox. Off keeps permission prompts, not OS isolation. Saves to global.",
    sandboxEnabled,
    sources?.sandbox,
  )];
  return [
    ...sandboxItem,
    {
      id: "mode",
      label: "Mode",
      description:
        "manual prompts; yolo approves everything except hard rules; auto adds a local classifier for workspace reads, writes, and sandboxed Bash. Saves to the scope below.",
      currentValue: modeValue,
      values: modeValues,
    },
    {
      id: "modeScope",
      label: "Save mode to",
      description:
        "Where the next mode change is stored: this session only, this project's permissions file (reuses the legacy file when present), or the global config",
      currentValue: modeScope,
      values: MODE_SCOPES,
    },
    toggleItem(
      "permissionReviewLog",
      "Permission review log",
      "Write permission request and decision audit events to the extension logs directory. Saves to global.",
      config.permissionReviewLog,
      sources?.permissionReviewLog,
    ),
    toggleItem(
      "debugLog",
      "Debug logging",
      "Write verbose pi-sentinel diagnostics to the extension logs directory. Saves to global.",
      config.debugLog,
      sources?.debugLog,
    ),
  ];
}


function formatLegacyModeFlags(layer: ModeLayer): string | undefined {
  if (!layer.legacyMode) return undefined;
  return Object.entries(layer.legacyMode)
    .map(([name, value]) => name + "=" + value)
    .join(", ");
}

function getSelectedModeLayer(
  modeLayers: ModeLayers,
  selectedScope: ModeScope,
): ModeLayer | undefined {
  const scopeLayer = modeLayers.layers.find((layer) => layer.id === selectedScope);
  if (selectedScope !== "project" || !scopeLayer?.savePath) return scopeLayer;
  return modeLayers.layers.find((layer) => layer.path === scopeLayer.savePath) ?? scopeLayer;
}

function getModeSaveShadowingLayer(
  modeLayers: ModeLayers,
  selectedScope: ModeScope,
): ModeLayer | undefined {
  const selectedLayer = getSelectedModeLayer(modeLayers, selectedScope);
  const scopeIndex = selectedLayer ? modeLayers.layers.indexOf(selectedLayer) : -1;
  const sourceIndex = modeLayers.layers.findIndex((layer) => layer.id === modeLayers.source);
  return sourceIndex >= 0 && scopeIndex >= 0 && sourceIndex < scopeIndex
    ? modeLayers.layers[sourceIndex]
    : undefined;
}

export function formatModeSaveNotice(
  mode: PermissionMode,
  scope: ModeScope,
  modeLayers: ModeLayers,
): string {
  const selectedLayer = getSelectedModeLayer(modeLayers, scope);
  const target = scope === "session"
    ? "memory only; lost on exit"
    : selectedLayer?.savePath ?? selectedLayer?.path ?? "path unavailable";
  const shadowingLayer = getModeSaveShadowingLayer(modeLayers, scope);
  const sourceLayer = modeLayers.layers.find((layer) => layer.id === modeLayers.source);
  const sourceName = sourceLayer ? layerLabel(sourceLayer) : modeLayers.source;
  const effectiveSource = shadowingLayer
    ? "from " + sourceName + ", which overrides the saved " + scope + " value"
    : "from " + sourceName;
  return "Saved mode '" + mode + "' → " + scope + " (" + target + "). Effective: " +
    modeLayers.effective + " (" + effectiveSource + ").";
}

function compactPath(path: string, cwd?: string): string {
  if (cwd) {
    const projectPath = relative(cwd, path);
    if (projectPath && projectPath !== ".." && !projectPath.startsWith(".." + sep)) {
      return "./" + projectPath;
    }
  }
  const home = homedir();
  return home && (path === home || path.startsWith(home + sep)) ? "~" + path.slice(home.length) : path;
}

/**
 * Compact header: the mode chain on one (wrapped) line with the winning layer
 * marked, then where each kind of change is written.
 */
function buildModeHeaderLines(
  modeLayers: ModeLayers,
  selectedScope: ModeScope,
  maxWidth?: number,
  cwd?: string,
): { chain: string[]; saves: string[] } {
  const selectedLayer = getSelectedModeLayer(modeLayers, selectedScope);
  const chain = modeLayers.layers
    .map((layer) => {
      const value = describeLayerMode(layer);
      const entry = layerLabel(layer) + " " + (value === "unset" ? "–" : value);
      return layer.id === modeLayers.source ? "▶ " + entry : entry;
    })
    .join(" · ");
  const saveTarget = selectedScope === "session"
    ? "memory only (lost on exit)"
    : selectedLayer
      ? compactPath(selectedLayer.savePath ?? selectedLayer.path, cwd)
      : "(no project directory)";
  const globalLayer = modeLayers.layers.find((layer) => layer.id === "global");
  const globalPath = globalLayer ? compactPath(globalLayer.path, cwd) : "(global config unavailable)";
  const wrap = (line: string): string[] =>
    maxWidth === undefined ? [line] : wrapTextWithAnsi(line, maxWidth);
  return {
    chain: wrap("Mode chain (top wins): " + chain),
    saves: [
      ...wrap("Mode saves to " + selectedScope + ": " + saveTarget),
      ...wrap("Other settings save to global: " + globalPath),
    ],
  };
}

/** Fit the header into `maxLines`, clipping the chain before the save targets. */
function fitHeaderLines(header: { chain: string[]; saves: string[] }, maxLines: number): string[] {
  const chainBudget = Math.max(0, maxLines - header.saves.length);
  if (header.chain.length <= chainBudget) return [...header.chain, ...header.saves];
  const chain = header.chain.slice(0, chainBudget);
  if (chain.length > 0) chain[chain.length - 1] = chain[chain.length - 1].replace(/.?$/, "…");
  return [...chain, ...header.saves].slice(0, Math.max(0, maxLines));
}

export function formatModeChain(
  modeLayers: ModeLayers,
  selectedScope: ModeScope,
  maxWidth?: number,
  cwd?: string,
): string {
  const header = buildModeHeaderLines(modeLayers, selectedScope, maxWidth, cwd);
  return [...header.chain, ...header.saves].join("\n");
}

export function applySetting(
  config: PermissionSystemExtensionConfig,
  id: string,
  value: string,
): PermissionSystemExtensionConfig {
  switch (id) {
    case "mode":
      return MODES.includes(value as PermissionMode)
        ? { ...config, mode: value as PermissionMode }
        : config;
    case "permissionReviewLog":
      return { ...config, permissionReviewLog: value === "on" };
    case "debugLog":
      return { ...config, debugLog: value === "on" };
    default:
      return config;
  }
}

export function mergeEffectiveConfigWithSelectedMode(
  effectiveConfig: PermissionSystemExtensionConfig,
  selectedMode: PermissionMode,
): PermissionSystemExtensionConfig {
  return { ...effectiveConfig, mode: selectedMode };
}

function getArgumentCompletions(
  argumentPrefix: string,
): Array<{ value: string; label: string; description: string }> | null {
  const normalized = argumentPrefix.trim().toLowerCase();
  if (normalized.includes(" ")) {
    return null;
  }

  const filtered = COMMAND_ARGUMENTS.filter((item) =>
    item.value.startsWith(normalized),
  );
  return filtered.length > 0 ? [...filtered] : null;
}

async function openSettingsModal(
  ctx: ExtensionCommandContext,
  controller: PermissionSystemConfigController,
): Promise<void> {
  const overlayOptions = {
    anchor: "center" as const,
    width: 82,
    maxHeight: "100%" as const,
    margin: 0,
  };

  // eslint-disable-next-line @typescript-eslint/no-invalid-void-type -- ctx.ui.custom<void> is valid; rule does not allow void in generic fn call type args
  await ctx.ui.custom<void>(
    (tui, _theme, _keybindings, done) => {
      let current = controller.getConfig();
      let selectedMode = current.mode;
      let modeScope: ModeScope = "global";
      let modeLayers = controller.getModeLayers?.(ctx.cwd);
      let sources = controller.getSettingSources?.(ctx.cwd);
      const headerText = new Text("", 0, 0);

      const buildItems = (): SettingItem[] => buildSettingItems(
        current,
        controller.getSandboxEnabled?.(),
        modeScope,
        modeLayers,
        sources,
      );
      const settingItems = buildItems();
      const warnIfProjectOverrides = (id: "permissionReviewLog" | "debugLog", label: string): void => {
        if (sources?.[id] !== "project") return;
        ctx.ui.notify(
          "Saved " + label + " to global, but the project config keeps it " + toOnOff(current[id]) + ".",
          "warning",
        );
      };
      const settingsList = new SettingsList(
        settingItems,
        10,
        getSettingsListTheme(),
        (id, newValue) => {
          if (id === "sandbox") {
            controller.setSandboxEnabled?.(newValue === "on", ctx);
          } else if (id === "modeScope") {
            modeScope = newValue as ModeScope;
          } else {
            const next = applySetting(current, id, newValue);
            const modeWasExplicitlySelected = id === "mode";
            const saved = controller.setConfig(next, ctx, modeWasExplicitlySelected, modeScope);
            const effectiveConfig = controller.getConfig();
            if (modeWasExplicitlySelected) {
              selectedMode = saved ? next.mode : effectiveConfig.mode;
            }
            current = mergeEffectiveConfigWithSelectedMode(effectiveConfig, selectedMode);
            modeLayers = controller.getModeLayers?.(ctx.cwd);
            sources = controller.getSettingSources?.(ctx.cwd);
            if (modeWasExplicitlySelected && saved && modeLayers) {
              ctx.ui.notify(
                formatModeSaveNotice(next.mode, modeScope, modeLayers),
                getModeSaveShadowingLayer(modeLayers, modeScope) ? "warning" : "info",
              );
            } else if (saved && (id === "permissionReviewLog" || id === "debugLog")) {
              warnIfProjectOverrides(id, id === "debugLog" ? "Debug logging" : "Permission review log");
            }
          }
          refreshItems();
        },
        () => done(),
      );

      const refreshItems = (): void => {
        sources = controller.getSettingSources?.(ctx.cwd);
        for (const fresh of buildItems()) {
          const item = settingItems.find((candidate) => candidate.id === fresh.id);
          if (!item) continue;
          item.values = fresh.values;
          settingsList.updateValue(fresh.id, fresh.currentValue);
        }
        settingsList.invalidate();
        headerText.invalidate();
      };

      return {
        render(width: number) {
          let settingsLines = settingsList.render(width);
          if (!modeLayers) return settingsLines;
          const height = tui.terminal?.rows ?? 24;
          const header = buildModeHeaderLines(modeLayers, modeScope, width, ctx.cwd);
          const headerHeight = header.chain.length + header.saves.length;
          if (settingsLines.length + headerHeight > height) {
            // Descriptions are supplementary; never let them push controls off-screen.
            const descriptions = settingItems.map((item) => item.description);
            for (const item of settingItems) item.description = undefined;
            settingsLines = settingsList.render(width);
            settingItems.forEach((item, index) => { item.description = descriptions[index]; });
          }
          headerText.setText(fitHeaderLines(header, height - settingsLines.length).join("\n"));
          return [...(height - settingsLines.length > 0 ? headerText.render(width) : []), ...settingsLines];
        },
        invalidate() {
          settingsList.invalidate();
          headerText.invalidate();
        },
        handleInput(data: string) {
          settingsList.handleInput(data);
          tui.requestRender();
        },
      };
    },
    { overlay: true, overlayOptions },
  );
}

function handleArgs(
  args: string,
  ctx: ExtensionCommandContext,
  controller: PermissionSystemConfigController,
): boolean {
  const normalized = args.trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  if (normalized === "show") {
    const rules = controller.getComposedRules?.();
    ctx.ui.notify(
      `pi-sentinel: ${summarizeConfig(controller.getConfig(), rules, controller.getAutoModeStatus?.())}`,
      "info",
    );
    return true;
  }

  if (normalized === "path") {
    ctx.ui.notify(
      `pi-sentinel config paths:\n${controller.getConfigPath(ctx.cwd)}`,
      "info",
    );
    return true;
  }

  if (normalized === "reset") {
    if (controller.resetConfig) {
      controller.resetConfig(ctx);
    } else {
      controller.setConfig(cloneDefaultConfig(), ctx, true, "global");
    }
    ctx.ui.notify("Permission system settings reset to defaults.", "info");
    return true;
  }

  if (normalized === "help") {
    ctx.ui.notify(USAGE_TEXT, "info");
    return true;
  }

  ctx.ui.notify(USAGE_TEXT, "warning");
  return true;
}

export function registerPermissionSystemCommand(
  pi: ExtensionAPI,
  controller: PermissionSystemConfigController,
): void {
  pi.registerCommand("sentinel", {
    description:
      "Configure pi-sentinel logging and yolo-mode behavior",
    getArgumentCompletions,
    handler: async (args, ctx) => {
      if (handleArgs(args, ctx, controller)) {
        return;
      }

      if (!ctx.hasUI) {
        ctx.ui.notify(
          "/sentinel requires interactive TUI mode.",
          "warning",
        );
        return;
      }

      await openSettingsModal(ctx, controller);
    },
  });
}
