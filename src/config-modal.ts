import { relative, sep } from "node:path";

import {
  type ExtensionAPI,
  type ExtensionCommandContext,
  getSettingsListTheme,
} from "@earendil-works/pi-coding-agent";
import {
  matchesKey,
  type SettingItem,
  SettingsList,
  Text,
  visibleWidth,
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

export function buildSettingItems(
  config: PermissionSystemExtensionConfig,
  sandboxEnabled?: boolean,
  modeScope: ModeScope = "global",
  modeLayers?: ModeLayers,
): SettingItem[] {
  const selectedModeLayer = modeLayers ? getSelectedModeLayer(modeLayers, modeScope) : undefined;
  const legacyFlags = selectedModeLayer ? formatLegacyModeFlags(selectedModeLayer) : undefined;
  const modeValue = !modeLayers
    ? config.mode
    : selectedModeLayer?.error
      ? "unreadable"
      : selectedModeLayer?.mode ?? (legacyFlags
        ? "legacy flags: " + legacyFlags
        : "inherits: " + modeLayers.effective);
  const inheritedModeIndex = modeValue.startsWith("inherits: ") && modeLayers
    ? MODES.indexOf(modeLayers.effective)
    : -1;
  const modeValues = inheritedModeIndex < 0
    ? MODES
    : [...MODES.slice(inheritedModeIndex + 1), ...MODES.slice(0, inheritedModeIndex + 1)];
  const sandboxItem: SettingItem[] = sandboxEnabled === undefined ? [] : [{
    id: "sandbox",
    label: "Bash sandbox",
    description: "Run Bash in SRT sandbox. Off keeps permission prompts, not OS isolation.",
    currentValue: toOnOff(sandboxEnabled),
    values: ON_OFF,
  }];
  return [
    ...sandboxItem,
    {
      id: "mode",
      label: "Mode",
      description:
        "manual prompts; yolo approves everything except hard rules; auto adds a local classifier for workspace reads, writes, and sandboxed Bash",
      currentValue: modeValue,
      values: modeValues,
    },
    {
      id: "modeScope",
      label: "Mode saves to",
      description:
        "Where the next mode change is stored: this session only, this project's permissions file (reuses the legacy file when present), or the global config",
      currentValue: modeScope,
      values: MODE_SCOPES,
    },
    {
      id: "permissionReviewLog",
      label: "Permission review log",
      description:
        "Write permission request and decision audit events to the extension logs directory",
      currentValue: toOnOff(config.permissionReviewLog),
      values: ON_OFF,
    },
    {
      id: "debugLog",
      label: "Debug logging",
      description:
        "Write verbose pi-sentinel diagnostics to the extension logs directory",
      currentValue: toOnOff(config.debugLog),
      values: ON_OFF,
    },
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
  const sourceName = modeLayers.layers.find((layer) => layer.id === modeLayers.source)?.name
    ?? modeLayers.source;
  const effectiveSource = shadowingLayer
    ? "from " + sourceName + ", which overrides the saved " + scope + " value"
    : "from " + sourceName;
  return "Saved mode '" + mode + "' → " + scope + " (" + target + "). Effective: " +
    modeLayers.effective + " (" + effectiveSource + ").";
}

function buildModeChainLines(
  modeLayers: ModeLayers,
  selectedScope: ModeScope,
  maxWidth?: number,
  cwd?: string,
) {
  const selectedLayer = getSelectedModeLayer(modeLayers, selectedScope);
  const compactPath = (id: ModeLayer["id"], path: string): string => {
    if (maxWidth === undefined || !id.startsWith("project") || !cwd) return path;
    const projectPath = relative(cwd, path);
    return projectPath && projectPath !== ".." && !projectPath.startsWith(".." + sep)
      ? "./" + projectPath
      : path;
  };
  const fitPath = (prefix: string, path: string): string => {
    if (maxWidth === undefined) return prefix + path;
    return wrapTextWithAnsi(prefix + path, maxWidth).join("\n");
  };
  const rows = modeLayers.layers.flatMap((layer) => {
    const legacyFlags = formatLegacyModeFlags(layer);
    const value = layer.error
      ? "— unreadable"
      : layer.mode !== undefined
        ? legacyFlags ? layer.mode + " (" + legacyFlags + ")" : layer.mode
        : legacyFlags ? "legacy flags: " + legacyFlags : "— not set";
    const selected = layer === selectedLayer ? " ← selected" : "";
    const row = "  " + layer.name + " " + value +
      " (" + compactPath(layer.id, layer.path) + ")" + selected;
    return maxWidth === undefined ? [row] : wrapTextWithAnsi(row, maxWidth);
  });
  const saveTarget = selectedScope === "session"
    ? "memory only (lost on exit)"
    : selectedLayer
      ? compactPath(selectedLayer.id, selectedLayer.savePath ?? selectedLayer.path)
      : "(no project directory)";
  const globalPath = modeLayers.layers.find((layer) => layer.id === "global")?.path
    ?? "(global config unavailable)";
  const sourceName = modeLayers.layers.find((layer) => layer.id === modeLayers.source)?.name
    ?? modeLayers.source;

  const effective = "Effective this session: " + modeLayers.effective + " (from " + sourceName + ")";
  return {
    rows,
    effective: maxWidth !== undefined && visibleWidth(effective) > maxWidth
      ? "Effective: " + modeLayers.effective + " ← " + sourceName
      : effective,
    selected: "Selected: " + (selectedLayer?.name ?? selectedScope) + " ← selected",
    save: fitPath("Saving Mode writes: ", saveTarget),
    global: fitPath("Logs & sandbox always write: ", globalPath),
  };
}

export function formatModeChain(
  modeLayers: ModeLayers,
  selectedScope: ModeScope,
  maxWidth?: number,
  cwd?: string,
): string {
  const chain = buildModeChainLines(modeLayers, selectedScope, maxWidth, cwd);
  return [
    "Mode chain (top wins):",
    ...chain.rows,
    chain.effective,
    chain.save,
    chain.global,
  ].join("\n");
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

function syncSettingValues(
  settingsList: SettingsList,
  config: PermissionSystemExtensionConfig,
): void {
  settingsList.updateValue(
    "permissionReviewLog",
    toOnOff(config.permissionReviewLog),
  );
  settingsList.updateValue("debugLog", toOnOff(config.debugLog));
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
      const modeChainText = new Text("", 0, 0);
      let chainOffset = 0;
      let chainPageSize = 1;
      let chainRowCount = 0;

      const settingItems = buildSettingItems(
        current,
        controller.getSandboxEnabled?.(),
        modeScope,
        modeLayers,
      );
      const settingsList = new SettingsList(
        settingItems,
        10,
        getSettingsListTheme(),
        (id, newValue) => {
          if (id === "sandbox") {
            controller.setSandboxEnabled?.(newValue === "on", ctx);
            const enabled = controller.getSandboxEnabled?.();
            if (enabled !== undefined) settingsList.updateValue("sandbox", toOnOff(enabled));
            return;
          }
          if (id === "modeScope") {
            modeScope = newValue as ModeScope;
            refreshModeDisplay();
            return;
          }
          const next = applySetting(current, id, newValue);
          const modeWasExplicitlySelected = id === "mode";
          const saved = controller.setConfig(next, ctx, modeWasExplicitlySelected, modeScope);
          const effectiveConfig = controller.getConfig();
          if (modeWasExplicitlySelected) {
            selectedMode = saved ? next.mode : effectiveConfig.mode;
          }
          current = mergeEffectiveConfigWithSelectedMode(effectiveConfig, selectedMode);
          syncSettingValues(settingsList, current);
          modeLayers = controller.getModeLayers?.(ctx.cwd);
          if (modeWasExplicitlySelected && saved && modeLayers) {
            ctx.ui.notify(
              formatModeSaveNotice(next.mode, modeScope, modeLayers),
              getModeSaveShadowingLayer(modeLayers, modeScope) ? "warning" : "info",
            );
          }
          refreshModeDisplay();
        },
        () => done(),
      );

      const refreshModeDisplay = (): void => {
        const modeItem = buildSettingItems(
          current,
          controller.getSandboxEnabled?.(),
          modeScope,
          modeLayers,
        ).find((item) => item.id === "mode");
        if (modeItem) {
          const settingModeItem = settingItems.find((item) => item.id === "mode");
          if (settingModeItem) settingModeItem.values = modeItem.values;
          settingsList.updateValue("mode", modeItem.currentValue);
        }
        chainOffset = 0;
        settingsList.invalidate();
        modeChainText.invalidate();
      };

      return {
        render(width: number) {
          let settingsLines = settingsList.render(width);
          if (!modeLayers) return settingsLines;
          const height = tui.terminal?.rows ?? 24;
          const chain = buildModeChainLines(modeLayers, modeScope, width, ctx.cwd);
          const title = "Mode chain (top wins) · PgUp/PgDn";
          // Reserve the longest page indicator, including any wrapping at narrow widths.
          const budgetTitle = title + " " + chain.rows.length + "/" + chain.rows.length;
          modeChainText.setText([
            budgetTitle, chain.effective, chain.selected, chain.save, chain.global,
          ].join("\n"));
          const fixedHeaderHeight = modeChainText.render(width).length;
          if (settingsLines.length + fixedHeaderHeight + 1 > height) {
            // Descriptions are supplementary; never let them push controls off-screen.
            const descriptions = settingItems.map((item) => item.description);
            for (const item of settingItems) item.description = undefined;
            settingsLines = settingsList.render(width);
            settingItems.forEach((item, index) => { item.description = descriptions[index]; });
          }
          chainPageSize = Math.max(1, height - settingsLines.length - fixedHeaderHeight);
          chainRowCount = chain.rows.length;
          const lastPage = Math.max(0, Math.ceil(chainRowCount / chainPageSize) - 1);
          chainOffset = Math.min(Math.floor(chainOffset / chainPageSize), lastPage) * chainPageSize;
          const pageTitle = chainRowCount > chainPageSize
            ? title + " " + (Math.floor(chainOffset / chainPageSize) + 1) + "/" + (lastPage + 1)
            : "Mode chain (top wins):";
          modeChainText.setText([
            pageTitle,
            chain.effective,
            chain.selected,
            ...chain.rows.slice(chainOffset, chainOffset + chainPageSize),
            chain.save,
            chain.global,
          ].join("\n"));
          return [...modeChainText.render(width), ...settingsLines];
        },
        invalidate() {
          settingsList.invalidate();
          modeChainText.invalidate();
        },
        handleInput(data: string) {
          if (matchesKey(data, "pageUp")) {
            chainOffset = Math.max(0, chainOffset - chainPageSize);
          } else if (matchesKey(data, "pageDown")) {
            const lastPage = Math.max(0, Math.ceil(chainRowCount / chainPageSize) - 1);
            chainOffset = Math.min(lastPage * chainPageSize, chainOffset + chainPageSize);
          } else {
            settingsList.handleInput(data);
          }
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
