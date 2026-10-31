import { homedir } from "node:os";
import { relative, sep } from "node:path";

import {
  type ExtensionAPI,
  type ExtensionCommandContext,
  getSelectListTheme,
  getSettingsListTheme,
} from "@earendil-works/pi-coding-agent";
import {
  type SelectItem,
  SelectList,
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
const MODE_SCOPES: readonly ModeScope[] = ["session", "project", "global"];
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
    value: "mode",
    label: "Set mode",
    description: "mode <manual|yolo|auto> [session|project|global]: set the mode, optionally in a specific scope",
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
  "Usage: /sentinel [show|path|mode <manual|yolo|auto> [session|project|global]|reset|help] " +
  "(or run /sentinel with no args to open settings modal)";

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
 * Scope a mode change saves to: the scope that supplies the current mode.
 * `PI_SENTINEL_MODE` cannot be written, so a change applies to the session,
 * the only layer above it; bundled defaults save to the global file.
 */
export function modeSaveScope(modeLayers: ModeLayers): ModeScope {
  const source = modeLayers.source;
  if (source === "session" || source === "environment") return "session";
  return source.startsWith("project") ? "project" : "global";
}

function modeSourceName(modeLayers: ModeLayers): string {
  const sourceLayer = modeLayers.layers.find((layer) => layer.id === modeLayers.source);
  return sourceLayer ? layerLabel(sourceLayer) : modeLayers.source;
}

/**
 * Scopes where saving a mode changes the effective mode: the scope that sets
 * it now first, then session and project overrides. A scope hidden by a
 * higher layer is left out (saving to project or global clears a session mode).
 */
export function modeTargetScopes(modeLayers: ModeLayers): ModeScope[] {
  const current = modeSaveScope(modeLayers);
  const takesEffect = (scope: ModeScope): boolean => {
    if (scope === "session") return true;
    const target = getSelectedModeLayer(modeLayers, scope);
    if (!target) return false;
    const above = modeLayers.layers.slice(0, modeLayers.layers.indexOf(target));
    return above.every((layer) => layer.id === "session" || describeLayerMode(layer) === "unset");
  };
  return [current, ...MODE_SCOPES.filter((scope) => scope !== current)].filter(takesEffect);
}

const MODE_CHOICE_SEPARATOR = "@";

const PICKER_SCOPE_DESCRIPTIONS: Readonly<Record<ModeScope, (isCurrent: boolean) => string>> = {
  session: (isCurrent) => isCurrent ? "set for this session" : "override for this session only",
  project: (isCurrent) => isCurrent ? "set in this project" : "override in this project",
  global: () => "set globally",
};

/** Picker entries for every mode in every scope where it would take effect. */
export function modeChoices(modeLayers: ModeLayers): SelectItem[] {
  const current = modeSaveScope(modeLayers);
  return modeTargetScopes(modeLayers).flatMap((scope) => MODES.map((mode) => {
    const isCurrent = scope === current && mode === modeLayers.effective;
    return {
      value: mode + MODE_CHOICE_SEPARATOR + scope,
      label: mode.padEnd(7) + scope + (isCurrent ? " ✓" : ""),
      description: PICKER_SCOPE_DESCRIPTIONS[scope](scope === current),
    };
  }));
}

/** Parse a picker value such as `yolo@session`. */
export function parseModeChoice(value: string): { mode: PermissionMode; scope?: ModeScope } | undefined {
  const [mode, scope] = value.split(MODE_CHOICE_SEPARATOR);
  if (!MODES.includes(mode as PermissionMode)) return undefined;
  if (scope === undefined) return { mode: mode as PermissionMode };
  return MODE_SCOPES.includes(scope as ModeScope)
    ? { mode: mode as PermissionMode, scope: scope as ModeScope }
    : undefined;
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
  modeLayers?: ModeLayers,
  sources?: SettingSources,
): SettingItem[] {
  const modeValue = modeLayers
    ? withSource(modeLayers.effective, modeSourceName(modeLayers))
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
        "manual prompts; yolo approves everything except hard rules; auto adds a local classifier for workspace reads, writes, and sandboxed Bash. Enter to pick a mode, or override it for this session or project.",
      currentValue: modeValue,
      values: modeValues,
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
  maxWidth?: number,
  cwd?: string,
): { chain: string[]; saves: string[] } {
  const selectedScope = modeSaveScope(modeLayers);
  const selectedLayer = getSelectedModeLayer(modeLayers, selectedScope);
  const chain = modeLayers.layers
    .map((layer) => {
      const value = describeLayerMode(layer);
      const entry = layerLabel(layer) + " " + (value === "unset" ? "–" : value);
      return layer.id === modeLayers.source ? "▶ " + entry : entry;
    })
    .join(" · ");
  const saveTarget = selectedScope === "session"
    ? modeLayers.source === "environment"
      ? "memory only, above PI_SENTINEL_MODE (lost on exit)"
      : "memory only (lost on exit)"
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
  maxWidth?: number,
  cwd?: string,
): string {
  const header = buildModeHeaderLines(modeLayers, maxWidth, cwd);
  return [...header.chain, ...header.saves].join("\n");
}

export function applySetting(
  config: PermissionSystemExtensionConfig,
  id: string,
  value: string,
): PermissionSystemExtensionConfig {
  switch (id) {
    case "mode": {
      const choice = parseModeChoice(value);
      return choice ? { ...config, mode: choice.mode } : config;
    }
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

const MODE_DESCRIPTIONS: Readonly<Record<PermissionMode, string>> = {
  manual: "Prompt for every gated request",
  yolo: "Approve everything except the hard rules",
  auto: "Local classifier approves eligible workspace requests",
};

const SCOPE_DESCRIPTIONS: Readonly<Record<ModeScope, string>> = {
  session: "This session only, in memory",
  project: "This project's .pi/permissions.json",
  global: "All projects: ~/.pi/agent/permissions.json",
};

/**
 * Pi passes the whole argument text as the prefix and replaces it with the
 * chosen value, so each completion carries the full argument string.
 */
export function getArgumentCompletions(
  argumentPrefix: string,
): Array<{ value: string; label: string; description: string }> | null {
  const words = argumentPrefix.trimStart().toLowerCase().split(/\s+/);
  let items: Array<{ value: string; label: string; description: string }>;
  if (words.length === 1) {
    items = COMMAND_ARGUMENTS
      .filter((item) => item.value.startsWith(words[0]))
      .map((item) => item.value === "mode" ? { ...item, value: "mode " } : { ...item });
  } else if (words[0] === "mode" && words.length === 2) {
    items = MODES
      .filter((mode) => mode.startsWith(words[1]))
      .map((mode) => ({ value: "mode " + mode + " ", label: mode, description: MODE_DESCRIPTIONS[mode] }));
  } else if (words[0] === "mode" && words.length === 3 && MODES.includes(words[1] as PermissionMode)) {
    items = MODE_SCOPES
      .filter((scope) => scope.startsWith(words[2]))
      .map((scope) => ({
        value: "mode " + words[1] + " " + scope,
        label: scope,
        description: SCOPE_DESCRIPTIONS[scope],
      }));
  } else {
    return null;
  }
  return items.length > 0 ? items : null;
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
      let modeLayers = controller.getModeLayers?.(ctx.cwd);
      let sources = controller.getSettingSources?.(ctx.cwd);
      const headerText = new Text("", 0, 0);

      const modePicker = (_currentValue: string, choose: (value?: string) => void): SelectList => {
        const choices = modeLayers ? modeChoices(modeLayers) : [];
        const picker = new SelectList(choices, Math.min(choices.length, 9), getSelectListTheme());
        const currentIndex = choices.findIndex((choice) => choice.label.endsWith(" ✓"));
        if (currentIndex >= 0) picker.setSelectedIndex(currentIndex);
        picker.onSelect = (item) => choose(item.value);
        picker.onCancel = () => choose();
        return picker;
      };
      const buildItems = (): SettingItem[] => buildSettingItems(
        current,
        controller.getSandboxEnabled?.(),
        modeLayers,
        sources,
      ).map((item) => item.id === "mode" && modeLayers
        ? { ...item, values: undefined, submenu: modePicker }
        : item);
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
          } else {
            const next = applySetting(current, id, newValue);
            const modeWasExplicitlySelected = id === "mode";
            const modeScope = (modeWasExplicitlySelected ? parseModeChoice(newValue)?.scope : undefined)
              ?? (modeLayers ? modeSaveScope(modeLayers) : "global");
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
          item.submenu = fresh.submenu;
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
          const header = buildModeHeaderLines(modeLayers, width, ctx.cwd);
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

function setModeFromArgs(
  args: string[],
  ctx: ExtensionCommandContext,
  controller: PermissionSystemConfigController,
): void {
  const [mode, scopeArg, ...rest] = args;
  if (!MODES.includes(mode as PermissionMode) || rest.length > 0
    || (scopeArg !== undefined && !MODE_SCOPES.includes(scopeArg as ModeScope))) {
    ctx.ui.notify("Usage: /sentinel mode <manual|yolo|auto> [session|project|global]", "warning");
    return;
  }
  const layersBefore = controller.getModeLayers?.(ctx.cwd);
  const scope = (scopeArg as ModeScope | undefined)
    ?? (layersBefore ? modeSaveScope(layersBefore) : "global");
  const next = { ...controller.getConfig(), mode: mode as PermissionMode };
  if (!controller.setConfig(next, ctx, true, scope)) return;
  const layers = controller.getModeLayers?.(ctx.cwd);
  if (layers) {
    ctx.ui.notify(
      formatModeSaveNotice(next.mode, scope, layers),
      getModeSaveShadowingLayer(layers, scope) ? "warning" : "info",
    );
  } else {
    ctx.ui.notify("Saved mode '" + next.mode + "' → " + scope + ".", "info");
  }
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

  if (normalized === "mode" || normalized.startsWith("mode ")) {
    setModeFromArgs(normalized.split(/\s+/).slice(1), ctx, controller);
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
