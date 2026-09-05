import type { PermissionSystemExtensionConfig } from "./extension-config";
import type { PermissionState } from "./types";
import { wildcardMatch } from "./wildcard-matcher";

const BUILT_IN_YOLO_ASK_BASH_PATTERNS = ["rm *"] as const;

export interface AskPermissionResolutionOptions extends YoloApprovalContext {
  config: PermissionSystemExtensionConfig;
  hasUI: boolean;
  isSubagent: boolean;
}

export interface YoloApprovalContext {
  toolName?: string | null;
  command?: string | null;
}

export function isYoloModeEnabled(
  config: PermissionSystemExtensionConfig,
): boolean {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-conversion -- typed as boolean but may be undefined at runtime (untyped callers); Boolean() guards against that
  return Boolean(config.yoloMode);
}

export function matchesYoloAskBashPattern(
  context: YoloApprovalContext,
  config: PermissionSystemExtensionConfig,
): boolean {
  const { command } = context;
  if (context.toolName !== "bash" || typeof command !== "string") {
    return false;
  }

  return (
    BUILT_IN_YOLO_ASK_BASH_PATTERNS.some((pattern) =>
      wildcardMatch(pattern, command),
    )
    || (config.yoloAskBashPatterns ?? []).some((pattern) =>
      wildcardMatch(pattern, command),
    )
  );
}

export function shouldAutoApprovePermissionState(
  state: PermissionState,
  config: PermissionSystemExtensionConfig,
  context: YoloApprovalContext = {},
): boolean {
  return (
    state === "ask"
    && isYoloModeEnabled(config)
    && !matchesYoloAskBashPattern(context, config)
  );
}

export function canResolveAskPermissionRequest(
  options: AskPermissionResolutionOptions,
): boolean {
  return (
    options.hasUI
    || options.isSubagent
    || shouldAutoApprovePermissionState("ask", options.config, options)
  );
}
