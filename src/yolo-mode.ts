import type { PermissionSystemExtensionConfig } from "./extension-config";
import { isPathOutsideWorkingDirectory } from "./path-utils";
import type { RuleOrigin } from "./rule";
import type { PermissionCheckResult, PermissionState } from "./types";
import { wildcardMatch } from "./wildcard-matcher";

const BUILT_IN_YOLO_ASK_BASH_PATTERNS = [
  "rm *",
  "ssh *",
  "scp *",
  "sftp *",
  "rsync *",
  "docker *",
  "podman *",
  "kubectl *",
  "helm *",
  "terraform *",
  "tofu *",
  "pulumi *",
  "aws *",
  "az *",
  "gcloud *",
  "gh *",
  "fly *",
  "vercel *",
  "wrangler *",
  "git clone *",
  "git fetch *",
  "git pull *",
  "git push *",
  "git ls-remote *",
] as const;

const YOLO_RELAXED_WRITE_TOOL_NAMES = new Set(["write", "edit"]);
const YOLO_RELAXABLE_DENY_ORIGIN: RuleOrigin = "bundled";

export interface AskPermissionResolutionOptions extends YoloApprovalContext {
  config: PermissionSystemExtensionConfig;
  hasUI: boolean;
  isSubagent: boolean;
}

export interface YoloApprovalContext {
  toolName?: string | null;
  command?: string | null;
  forcePromptInYolo?: boolean;
}

type BundledToolDenyRelaxationOptions = {
  config: PermissionSystemExtensionConfig;
  toolName: string;
  path?: string | null;
  cwd?: string;
  toolPermission: Pick<PermissionCheckResult, "state" | "origin">;
  hasExternalDirectoryApproval?: boolean;
};

export function isYoloModeEnabled(
  config: PermissionSystemExtensionConfig,
): boolean {
  return config.mode === "yolo" || config.mode === "yolo-auto";
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
    && context.forcePromptInYolo !== true
    && !matchesYoloAskBashPattern(context, config)
  );
}

export function shouldRelaxBundledToolDenyInYolo(
  options: BundledToolDenyRelaxationOptions,
): boolean {
  if (!isYoloModeEnabled(options.config)) {
    return false;
  }

  if (!YOLO_RELAXED_WRITE_TOOL_NAMES.has(options.toolName)) {
    return false;
  }

  if (
    options.toolPermission.state !== "deny"
    || options.toolPermission.origin !== YOLO_RELAXABLE_DENY_ORIGIN
  ) {
    return false;
  }

  if (!options.path || !options.cwd) {
    return false;
  }

  if (!isPathOutsideWorkingDirectory(options.path, options.cwd)) {
    return true;
  }

  return options.hasExternalDirectoryApproval === true;
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
