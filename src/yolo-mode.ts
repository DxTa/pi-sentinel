import { bashInnerCommands, bashLiteralWord, bashWords, splitBashSegments } from "./bash-segments";
import type { PermissionSystemExtensionConfig } from "./extension-config";
import {
  isPathOutsideWorkingDirectory,
  isPathWithinCanonicalWorkingDirectory,
} from "./path-utils";
import type { RuleOrigin } from "./rule";
import type { PermissionCheckResult, PermissionState } from "./types";
import { wildcardMatch } from "./wildcard-matcher";

/* kubectl verbs that change the cluster; reads such as get, describe and logs pass. */
const KUBECTL_WRITE_VERBS = new Set([
  "apply", "create", "delete", "edit", "patch", "replace", "set", "scale", "drain", "cordon", "uncordon",
  "taint", "label", "annotate", "autoscale", "run", "expose", "cp",
]);
const KUBECTL_READ_VERBS = new Set([
  "get", "describe", "logs", "top", "explain", "api-resources", "api-versions", "version", "config",
  "cluster-info", "auth", "diff", "wait", "port-forward", "events", "completion", "plugin", "kustomize", "options", "help",
]);
const KUBECTL_READ_ROLLOUTS = new Set(["status", "history"]);
/* Global options that take the next word as their value. */
const KUBECTL_VALUE_OPTIONS = new Set([
  "-n", "--namespace", "--context", "--cluster", "--kubeconfig", "-s", "--server", "--user", "--token", "--as",
  "--as-group", "--as-uid", "--request-timeout", "--cache-dir", "--certificate-authority", "--client-certificate",
  "--client-key", "--tls-server-name", "--username", "--password", "--profile", "--profile-output", "-v", "--v",
  "--vmodule", "--log-flush-frequency",
]);
const GIT_VALUE_OPTIONS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--exec-path", "--config-env"]);

/* Position of the subcommand: the first word that is not an option or an option value. */
function subcommandIndex(words: string[], valueOptions: ReadonlySet<string>): number {
  let i = 1;
  while (words[i]?.startsWith("-")) i += valueOptions.has(words[i]!) ? 2 : 1;
  return i;
}

function isKubectlWrite(words: string[]): boolean {
  const at = subcommandIndex(words, KUBECTL_VALUE_OPTIONS);
  const verb = words[at] ?? "";
  if (verb === "rollout") return !KUBECTL_READ_ROLLOUTS.has(words[at + 1] ?? "");
  if (KUBECTL_WRITE_VERBS.has(verb)) return true;
  // An unknown subcommand may be an option value we did not recognize, so look at every word.
  return !KUBECTL_READ_VERBS.has(verb) && words.some((word) => KUBECTL_WRITE_VERBS.has(word));
}

/** git push by executable name, so `/usr/bin/git` and tab spacing count. */
function isGitPushWords(words: readonly string[]): boolean {
  const normalized = words.map((word) => bashLiteralWord(word) ?? word);
  const subcommand = subcommandIndex(normalized, GIT_VALUE_OPTIONS);
  const executable = bashLiteralWord(words[0]);
  if (
    executable?.slice(executable.lastIndexOf("/") + 1) !== "git"
    || normalized[subcommand] !== "push"
  ) return false;

  for (let index = 1; index <= subcommand;) {
    const word = bashLiteralWord(words[index]);
    if (word === null) return false;
    index += GIT_VALUE_OPTIONS.has(word) ? 2 : 1;
  }
  return true;
}

export function isGitExecutable(word: string): boolean {
  return word.slice(word.lastIndexOf("/") + 1) === "git";
}

/** Only `git push` and `git -C <path> push` are plain; other forms that name push need a prompt. */
export function isPlainGitPushWords(words: readonly string[]): boolean {
  const normalized = words.map((word) => bashLiteralWord(word) ?? word);
  const verbAt = normalized[1] === "-C" ? 3 : 1;
  return isGitExecutable(normalized[0] ?? "") && normalized[verbAt] === "push";
}

/** A git push that is not plain, including one behind an env prefix or wrapper that the inner parse drops. */
function isNonPlainGitPush(words: readonly string[]): boolean {
  const gitAt = words.findIndex((word) => isGitExecutable(bashLiteralWord(word) ?? word));
  return gitAt !== -1 && isGitPushWords(words.slice(gitAt)) && !isPlainGitPushWords(words);
}

const PACKAGE_PUBLISHERS = new Set(["npm", "pnpm", "yarn"]);

function isBuiltInAskCommand(words: string[]): boolean {
  const name = words[0]?.slice(words[0].lastIndexOf("/") + 1);
  if (name === "rm" || name === "ssh") return true;
  // shortcut: any `publish` word counts, so `npm run publish` also prompts; parse npm flags if that gets noisy.
  if (name && PACKAGE_PUBLISHERS.has(name) && words.includes("publish")) return true;
  if (isNonPlainGitPush(words)) return true;
  return name === "kubectl" && isKubectlWrite(words);
}

export function matchesGitPushCommand(command: string): boolean {
  return (bashInnerCommands(command)?.commands ?? [command]).some((part) => {
    const words = bashWords(part);
    return words !== null && isGitPushWords(words);
  });
}

function matchesBuiltInAsk(command: string): boolean {
  return [...(bashInnerCommands(command)?.commands ?? [command]), ...(splitBashSegments(command) ?? [])].some((part) => {
    const words = bashWords(part);
    return words !== null && isBuiltInAskCommand(words);
  });
}

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
  return config.mode === "yolo" || config.mode === "auto";
}

export function matchesYoloAskBashPattern(
  context: YoloApprovalContext,
  config: PermissionSystemExtensionConfig,
): boolean {
  const { command } = context;
  if (context.toolName !== "bash" || typeof command !== "string") {
    return false;
  }

  return matchesBuiltInAsk(command) || matchesBashAskPattern(config.yoloAskBashPatterns ?? [], command);
}

/**
 * Ask patterns match the whole command, each segment and each inner command, so
 * `cd x && rm y`, a loop body or `bash -c 'rm y'` cannot hide a pattern.
 */
export function matchesBashAskPattern(patterns: readonly string[], command: string): boolean {
  const candidates = [
    command,
    ...(splitBashSegments(command) ?? []),
    ...(bashInnerCommands(command)?.commands ?? []),
  ];
  return patterns.some((pattern) => candidates.some((candidate) => wildcardMatch(pattern, candidate)));
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

export function shouldAutoApproveForwardedPermissionRequest(
  config: PermissionSystemExtensionConfig,
  context: YoloApprovalContext,
): boolean {
  return (
    config.mode === "yolo"
    && shouldAutoApprovePermissionState("ask", config, context)
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

  // Classic yolo writes anywhere; forbidden system and credential paths are denied before this runs.
  if (options.config.mode === "yolo") {
    return true;
  }

  if (
    !isPathOutsideWorkingDirectory(options.path, options.cwd)
    && isPathWithinCanonicalWorkingDirectory(options.path, options.cwd)
  ) {
    return true;
  }

  return options.hasExternalDirectoryApproval === true;
}

const EXPLICIT_ALLOW_ORIGINS: readonly RuleOrigin[] = ["global", "project", "session"];

/** In auto, only an allow the user wrote or approved skips the model; defaults go to the classifier like an ask. */
export function gateNonExplicitAllowForAuto<T extends { state: PermissionState; origin: RuleOrigin }>(
  mode: PermissionSystemExtensionConfig["mode"],
  check: T,
): T {
  return mode === "auto" && check.state === "allow" && !EXPLICIT_ALLOW_ORIGINS.includes(check.origin)
    ? { ...check, state: "ask" }
    : check;
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
