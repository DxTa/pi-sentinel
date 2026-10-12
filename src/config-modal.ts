import {
  type ExtensionAPI,
  type ExtensionCommandContext,
  getSettingsListTheme,
} from "@earendil-works/pi-coding-agent";
import { type SettingItem, SettingsList } from "@earendil-works/pi-tui";

import {
  DEFAULT_EXTENSION_CONFIG,
  type ModeScope,
  type PermissionMode,
  type PermissionSystemExtensionConfig,
} from "./extension-config";
import type { Ruleset } from "./rule";

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
  /** Optional: returns the composed config-layer ruleset for origin display. */
  getComposedRules?(): Ruleset;
  /** Optional runtime state for model-backed yolo-auto worker diagnostics. */
  getYoloAutoStatus?(): string;
  /** Optional: effective sandbox state and global toggle. */
  getSandboxEnabled?(): boolean;
  setSandboxEnabled?(enabled: boolean, ctx: ExtensionCommandContext): void;
}

const ON_OFF = ["on", "off"];
const MODES: PermissionMode[] = ["manual", "yolo", "yolo-auto"];
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
  yoloAutoStatus?: string,
): string {
  const knobs = [
    `mode=${config.mode}`,
    `permissionReviewLog=${toOnOff(config.permissionReviewLog)}`,
    `debugLog=${toOnOff(config.debugLog)}`,
  ].join(", ");
  const rulesSuffix = rules ? formatRulesSummary(rules) : "";
  const workerSuffix = yoloAutoStatus ? `, ${yoloAutoStatus}` : "";
  return `${knobs}${workerSuffix}${rulesSuffix}`;
}

export function buildSettingItems(
  config: PermissionSystemExtensionConfig,
  sandboxEnabled?: boolean,
  modeScope: ModeScope = "global",
): SettingItem[] {
  const sandboxItem: SettingItem[] = sandboxEnabled === undefined ? [] : [{
    id: "sandbox",
    label: "Bash sandbox",
    description: "Run Bash inside the SRT sandbox. Off keeps permission prompts but drops OS-level isolation",
    currentValue: toOnOff(sandboxEnabled),
    values: ON_OFF,
  }];
  return [
    ...sandboxItem,
    {
      id: "mode",
      label: "Mode",
      description:
        "Manual prompts; yolo auto-approves safe checks; yolo-auto uses model-backed workspace read/list approval with classic yolo elsewhere",
      currentValue: config.mode,
      values: MODES,
    },
    {
      id: "modeScope",
      label: "Mode scope",
      description:
        "Where the next mode change is stored: this session only, this project's .pi/permissions.json, or the global config",
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
  settingsList.updateValue("mode", config.mode);
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
    maxHeight: "85%" as const,
    margin: 1,
  };

  // eslint-disable-next-line @typescript-eslint/no-invalid-void-type -- ctx.ui.custom<void> is valid; rule does not allow void in generic fn call type args
  await ctx.ui.custom<void>(
    (_tui, _theme, _keybindings, done) => {
      let current = controller.getConfig();
      let selectedMode = current.mode;
      let modeScope: ModeScope = "global";
      const settingsList = new SettingsList(
        buildSettingItems(current, controller.getSandboxEnabled?.(), modeScope),
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
        },
        () => done(),
      );

      return settingsList;
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
      `pi-sentinel: ${summarizeConfig(controller.getConfig(), rules, controller.getYoloAutoStatus?.())}`,
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
