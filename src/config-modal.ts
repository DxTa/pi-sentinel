import {
  type ExtensionAPI,
  type ExtensionCommandContext,
  getSettingsListTheme,
} from "@earendil-works/pi-coding-agent";
import { type SettingItem, SettingsList } from "@earendil-works/pi-tui";

import {
  DEFAULT_EXTENSION_CONFIG,
  type PermissionSystemExtensionConfig,
} from "./extension-config";
import type { Ruleset } from "./rule";

interface PermissionSystemConfigController {
  getConfig(): PermissionSystemExtensionConfig;
  setConfig(
    next: PermissionSystemExtensionConfig,
    ctx: ExtensionCommandContext,
  ): void;
  resetConfig?(ctx: ExtensionCommandContext): void;
  getConfigPath(cwd?: string | null): string;
  /** Optional: returns the composed config-layer ruleset for origin display. */
  getComposedRules?(): Ruleset;
  /** Optional runtime state for model-backed yolo-auto worker diagnostics. */
  getYoloAutoStatus?(): string;
}

const ON_OFF = ["on", "off"];
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
    yoloMode: DEFAULT_EXTENSION_CONFIG.yoloMode,
    yoloAutoMode: DEFAULT_EXTENSION_CONFIG.yoloAutoMode,
    yoloAutoMaxLevel: DEFAULT_EXTENSION_CONFIG.yoloAutoMaxLevel,
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
    `yoloMode=${toOnOff(config.yoloMode)}`,
    `yoloAutoMode=${toOnOff(config.yoloAutoMode)} (max=${config.yoloAutoMaxLevel})`,
    `permissionReviewLog=${toOnOff(config.permissionReviewLog)}`,
    `debugLog=${toOnOff(config.debugLog)}`,
  ].join(", ");
  const rulesSuffix = rules ? formatRulesSummary(rules) : "";
  const workerSuffix = yoloAutoStatus ? `, ${yoloAutoStatus}` : "";
  return `${knobs}${workerSuffix}${rulesSuffix}`;
}

function buildSettingItems(
  config: PermissionSystemExtensionConfig,
): SettingItem[] {
  return [
    {
      id: "yoloMode",
      label: "YOLO mode",
      description:
        "Auto-approve eligible ask-state permission checks while still prompting for protected bash commands and first-time external writes",
      currentValue: toOnOff(config.yoloMode),
      values: ON_OFF,

    },
    {
      id: "yoloAutoMode",
      label: "YOLO auto",
      description:
        "Enable model-backed auto-approval for eligible workspace-local reads and directory listings",
      currentValue: toOnOff(config.yoloAutoMode),
      values: ON_OFF,
    },
    {
      id: "yoloAutoMaxLevel",
      label: "YOLO auto level",
      description: "Maximum automatic-approval level; L3 remains advisory escalation only",
      currentValue: config.yoloAutoMaxLevel,
      values: ["l1", "l2", "l3"],
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

function applySetting(
  config: PermissionSystemExtensionConfig,
  id: string,
  value: string,
): PermissionSystemExtensionConfig {
  switch (id) {
    case "yoloMode":
      return { ...config, yoloMode: value === "on" };
    case "yoloAutoMode":
      return { ...config, yoloAutoMode: value === "on" };
    case "yoloAutoMaxLevel":
      return value === "l1" || value === "l2" || value === "l3"
        ? { ...config, yoloAutoMaxLevel: value }
        : config;
    case "permissionReviewLog":
      return { ...config, permissionReviewLog: value === "on" };
    case "debugLog":
      return { ...config, debugLog: value === "on" };
    default:
      return config;
  }
}

function syncSettingValues(
  settingsList: SettingsList,
  config: PermissionSystemExtensionConfig,
): void {
  settingsList.updateValue("yoloMode", toOnOff(config.yoloMode));
  settingsList.updateValue("yoloAutoMode", toOnOff(config.yoloAutoMode));
  settingsList.updateValue("yoloAutoMaxLevel", config.yoloAutoMaxLevel);
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
      const settingsList = new SettingsList(
        buildSettingItems(current),
        10,
        getSettingsListTheme(),
        (id, newValue) => {
          current = applySetting(current, id, newValue);
          controller.setConfig(current, ctx);
          current = controller.getConfig();
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
      controller.setConfig(cloneDefaultConfig(), ctx);
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
