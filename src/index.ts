/**
 * Pi Permission System — standalone permission and sandbox extension.
 *
 * This extension provides:
 * - Network domain gating (from domain-gate.ts)
 * - SRT sandboxing through sandbox-runtime
 * - Dynamic sandbox rules with ask/allow/deny UX
 * - Unified config with permission, network, and sandbox sections
 */

import { scoreWithHistory } from "./yolo-auto-scorer";
import { NEIGHBOUR_WINDOW_MS, summarizeNeighbours } from "./yolo-auto-neighbours";
import { openDecisionStore, type DecisionStore } from "./yolo-auto-decision-store";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { ChildProcess } from "node:child_process";
import { toRecord } from "./common";

// ── Extension imports ────────────────────────────────────────────────────
import { registerPermissionSystemCommand } from "./config-modal";
import {
  getBundledConfigPath,
  getGlobalConfigDir,
  getGlobalConfigPath,
  getLegacyGlobalPolicyPath,
  getLegacyProjectConfigPath,
  getLegacyProjectExtensionConfigPath,
  getLegacyProjectPolicyPath,
  getProjectConfigPath,
} from "./config-paths";
import { EXTENSION_ROOT } from "./extension-config";
import type { PermissionForwardingDeps } from "./forwarded-permissions/polling";
import { ForwardingManager } from "./forwarding-manager";
import {
  AgentPrepHandler,
  PermissionGateHandler,
  SessionLifecycleHandler,
} from "./handlers";
import { buildInputForSurface } from "./input-normalizer";
import { requestPermissionDecisionFromUi } from "./permission-dialog";
import { registerPermissionRpcHandlers } from "./permission-event-rpc";
import { emitReadyEvent } from "./permission-events";
import { PermissionPrompter } from "./permission-prompter";
import { YoloAutoEvaluator } from "./yolo-auto-evaluator";
import { writeYoloAutoCalibrationRecord } from "./yolo-auto-calibration";
import {
  createUnixSocketWorkerTransport,
  YoloAutoBuildMismatchError,
  YoloAutoClient,
} from "./yolo-auto-client";
import { isUnixSocketActive, spawnDetachedYoloAutoWorker, waitForWorkerStartup } from "./yolo-auto-startup";
import { YOLO_AUTO_BUILD_ID } from "./yolo-auto-build";
import { PromptWaitTracker } from "./prompt-state";
import { getHardBlockedBashMutationPaths } from "./handlers/gates/bash-external-directory.js";
import { extractExternalPathsFromBashCommand } from "./handlers/gates/bash-path-extractor.js";
import { isReadOnlyBashChain, isReadOnlyBashDiagnostic } from "./bash-command-safety";
import {
  getPathBearingToolPath,
  isPathWithinDirectory,
  isSensitiveEnvPath,
  isWorkspaceLocalFileOperation,
  resolveReadPathForComparison,
} from "./path-utils";
import { PermissionSession } from "./permission-session";
import { matchTrustedPiRequest } from "./handlers/gates/trusted-pi-dirs";
import {
  applySessionModeEvent,
  createExtensionRuntime,
  getModeLayers,
  logResolvedConfigPaths,
  persistPermissionRule,
  recordInteractiveSession,
  refreshExtensionConfig,
  resetExtensionConfig,
  resolveInteractiveSessionFallback,
  saveExtensionConfig,
  saveSandboxEnabled,
} from "./runtime";
import type { PermissionsService } from "./service";
import {
  publishPermissionsService,
  unpublishPermissionsService,
} from "./service";
import { createSessionLogger } from "./session-logger";
import { isSubagentExecutionContext } from "./subagent-context";
import {
  canResolveAskPermissionRequest,
  shouldAutoApproveForwardedPermissionRequest,
} from "./yolo-mode";

// ── Our modules ──────────────────────────────────────────────────────────
import { loadDomainPolicy, type DomainGateConfig } from "./network/config.js";
import { registerDomainGateCommand } from "./network/domain-gate.js";
import { clearSessionNetworkApprovals, getSessionNetworkApprovals, handleNetworkToolCall, handleNetworkUserBash } from "./network/network-gate-handler.js";
import { normalizeSandboxConfig, resolveSandboxProfile, type SandboxConfig, validateSandboxGrantPath } from "./sandbox/settings.js";
import type { ResolvedSandboxProfile, UnmaskedPath } from "./sandbox/types.js";
import {
  isDockerCommand,
  isHostCapabilityBootstrapCommand,
  shouldBypassSandboxCommand,
} from "./sandbox/bypass-command.js";
import {
  createSrtBackend,
  DEFAULT_SRT_HELPER_ENV,
  DEFAULT_SRT_HELPER_INPUT_FILE_ENV,
} from "./sandbox/backends/srt-backend.js";
import { summarizeEnvironmentSizes } from "./sandbox/spawn-diagnostics.js";
import {
  maskDotenvReadResult,
  maskDotenvText,
  maskSecretValues,
  parseDotenvValues,
  readDotenvSourceWithinLimit,
} from "./env-mask";
import { isProtectedCredentialReadPath, protectedBashReadPaths } from "./protected-read";

import { defaultSrtHelperPath, defaultSrtStatus } from "./sandbox/srt-status.js";
import { SandboxPolicyManager, type Grant, type GrantDuration } from "./sandbox/policy-manager.js";
import { createSandboxRuntimeLoader } from "./sandbox/runtime-lazy.js";
import { promptSandboxGrant } from "./sandbox/sandbox-prompt.js";
import {
  DEFAULT_MASKED_PATTERNS,
  classifyMaskedPathKind,
  detectMaskedFileAccess,
  formatMaskedAccessSuggestion,
  isPathMasked,
} from "./sandbox/masked-file-gate.js";
import {
  detectExternalPaths,
  detectExternalWritePaths,
  formatExternalPathPrompt,
  resolveRepoRoot,
} from "./sandbox/external-path-gate.js";
import {
  getScopedConfigPath,
  loadMergedScopedConfig,
  readConfigFile,
  resolveConfinedConfigPath,
  writeConfigFile,
  persistNetworkGrantToConfig,
  persistSandboxNetworkGrantToConfig,
  persistSandboxPathGrantToConfig,
  removeNetworkGrantFromConfig,
  removeSandboxNetworkGrantFromConfig,
  removeSandboxPathGrantFromConfig,
  type PersistentApprovalScope,
} from "./scoped-config";
import { detectImplicitAuthAccess, type MaskedAuthKind } from "./sandbox/auth-path-detection.js";
import {
  addMaskedAuthPersistentGrant,
  addMaskedAuthSessionGrant,
  clearMaskedAuthSessionGrants,
  getMaskedAuthPersistentGrants,
  getMaskedAuthSessionGrants,
} from "./sandbox/masked-auth-grants.js";
import { resolveAuthExceptionPolicy, type ResolvedAuthException } from "./sandbox/auth-exception-policy.js";
import { existsSync, lstatSync, realpathSync, unlinkSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { homedir } from "node:os";
import { createPiClipboardTempCleanup } from "./clipboard-temp-cleanup.js";

/** Replace a tool result with `****`, including truncation metadata; never throws. */
function fullyRedactedResult(details: unknown): { content: { type: "text"; text: string }[]; details?: unknown } {
  const content = [{ type: "text" as const, text: "****" }];
  try {
    const masked = maskDotenvReadDetails(details, () => "****");
    return masked === undefined ? { content } : { content, details: masked };
  } catch {
    return { content };
  }
}

function maskDotenvReadDetails(details: unknown, maskText: (text: string) => string): unknown {
  const detailsRecord = toRecord(details);
  const truncation = toRecord(detailsRecord.truncation);
  if (typeof truncation.content !== "string") return details;
  return {
    ...detailsRecord,
    truncation: { ...truncation, content: maskText(truncation.content) },
  };
}

// ── Config helpers ───────────────────────────────────────────────────────

function getAgentDir(): string {
  return process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent");
}


function getExtensionDir(): string {
  return join(getAgentDir(), "extensions", "pi-sentinel");
}

interface YoloAutoWorkerHandle {
  process?: ChildProcess;
  startupSignal: Promise<void>;
}

async function startYoloAutoWorker(
  socketPath: string,
  agentDir: string,
  writeDebugLog: (event: string, details?: Record<string, unknown>) => void,
): Promise<YoloAutoWorkerHandle> {
  if (await isUnixSocketActive(socketPath)) {
    writeDebugLog("yolo_auto.worker_reused", { reason: "active_socket" });
    return { startupSignal: Promise.resolve() };
  }
  const workerPath = join(EXTENSION_ROOT, "src", "yolo-auto-worker-main.ts");
  const modelDir = process.env.PI_SENTINEL_YOLO_AUTO_MODEL_DIR
    || join(agentDir, "runtime", "pi-sentinel", "yolo-auto", "models");
  const args = [
    "--experimental-strip-types",
    workerPath,
    "--socket",
    socketPath,
    "--model-dir",
    modelDir,
  ];
  try {
    const worker = await spawnDetachedYoloAutoWorker(agentDir, process.execPath, args);
    const startupSignal = worker.startupSignal.catch((error: unknown) => {
      writeDebugLog("yolo_auto.worker_unavailable", { reason: "spawn_error" });
      throw error;
    });
    void startupSignal.catch(() => undefined);
    return { process: worker.process, startupSignal };
  } catch (error) {
    writeDebugLog("yolo_auto.worker_unavailable", { reason: "spawn_error" });
    const startupSignal = Promise.reject(error);
    void startupSignal.catch(() => undefined);
    return { startupSignal };
  }

}

interface UnifiedConfig {
  debugLog?: boolean;
  permissionReviewLog?: boolean;
  mode?: "manual" | "yolo" | "yolo-auto";
  permission?: Record<string, unknown>;
  network?: DomainGateConfig;
  sandbox?: Record<string, unknown>;
}

function loadConfig(cwd?: string): UnifiedConfig {
  return loadMergedScopedConfig(getAgentDir(), cwd ?? null).merged as UnifiedConfig;
}

function getSafeScopedConfigPath(
  scope: PersistentApprovalScope,
  cwd: string | undefined,
): string {
  const configPath = getScopedConfigPath(getAgentDir(), cwd ?? null, scope);
  if (scope === "workspace" && cwd) resolveConfinedConfigPath(configPath, cwd);
  return configPath;
}

function persistScopedSandboxPathGrant(
  scope: PersistentApprovalScope,
  cwd: string | undefined,
  targetPath: string,
  mode: "ro" | "rw",
): string {
  const configPath = getScopedConfigPath(getAgentDir(), cwd ?? null, scope);
  const workspaceRoot = scope === "workspace" && cwd ? cwd : undefined;
  const safeConfigPath = getSafeScopedConfigPath(scope, cwd);
  persistSandboxPathGrantToConfig(configPath, targetPath, mode, workspaceRoot);
  return safeConfigPath;
}

function persistScopedNetworkGrant(
  scope: PersistentApprovalScope,
  cwd: string | undefined,
  domain: string,
  state: "allow" | "deny" = "allow",
): string {
  const configPath = getScopedConfigPath(getAgentDir(), cwd ?? null, scope);
  const workspaceRoot = scope === "workspace" && cwd ? cwd : undefined;
  const safeConfigPath = getSafeScopedConfigPath(scope, cwd);
  persistNetworkGrantToConfig(configPath, domain, state, workspaceRoot);
  return safeConfigPath;
}

function persistScopedSandboxNetworkGrant(
  scope: PersistentApprovalScope,
  cwd: string | undefined,
): string {
  const configPath = getScopedConfigPath(getAgentDir(), cwd ?? null, scope);
  const workspaceRoot = scope === "workspace" && cwd ? cwd : undefined;
  const safeConfigPath = getSafeScopedConfigPath(scope, cwd);
  persistSandboxNetworkGrantToConfig(configPath, workspaceRoot);
  return safeConfigPath;
}

/** Parse a human-readable TTL string into milliseconds. */
function parseTTL(ttl: string): GrantDuration {
  if (ttl === "once" || ttl === "session" || ttl === "always") return ttl;
  const match = ttl.match(/^(\d+)(ms|s|m|h)?$/);
  if (!match) throw new Error(`Invalid TTL '${ttl}'. Use once, session, always, 30m, or 1h.`);
  const num = parseInt(match[1], 10);
  const unit = match[2] || "m";
  switch (unit) {
    case "ms": return num;
    case "s": return num * 1000;
    case "m": return num * 60_000;
    case "h": return num * 3_600_000;
    default: throw new Error(`Invalid TTL '${ttl}'.`);
  }
}

function tokenizeSandboxCommandArgs(args: string): string[] {
  if (args.includes("\u0000")) throw new Error("Sandbox grant arguments contain NUL byte.");
  const tokens: string[] = [];
  let token = "";
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (const char of args.trim()) {
    if (escaped) {
      token += char;
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (quote) {
      if (char === quote) quote = undefined;
      else token += char;
    } else if (char === "'" || char === '"') {
      quote = char;
    } else if (/\s/.test(char)) {
      if (token) {
        tokens.push(token);
        token = "";
      }
    } else {
      token += char;
    }
  }
  if (escaped) token += "\\";
  if (quote) throw new Error("Unclosed quote in sandbox grant arguments.");
  if (token) tokens.push(token);
  return tokens;
}

function expandGrantPath(rawPath: string, cwd: string): string {
  const expanded = rawPath === "~"
    ? homedir()
    : rawPath.startsWith("~/")
      ? join(homedir(), rawPath.slice(2))
      : rawPath;
  return isAbsolute(expanded) ? expanded : resolve(cwd, expanded);
}

function normalizeGrantPath(rawPath: string, cwd: string): string {
  let candidate = expandGrantPath(rawPath, cwd);
  const suffix: string[] = [];
  while (true) {
    try {
      const stats = lstatSync(candidate);
      if (stats.isSocket()) throw new Error("Sandbox grants cannot target Unix sockets.");
      const canonical = realpathSync.native(candidate);
      return suffix.length === 0 ? canonical : resolve(canonical, ...suffix.reverse());
    } catch (error) {
      if (error instanceof Error && /Unix sockets/.test(error.message)) throw error;
      const parent = dirname(candidate);
      if (parent === candidate) throw new Error(`Sandbox grant path does not exist: ${rawPath}`);
      suffix.push(candidate.slice(parent.length + 1));
      candidate = parent;
    }
  }
}

function validateGrantPath(targetPath: string, profile: ResolvedSandboxProfile, mode: "ro" | "rw"): void {
  const normalized = resolve(targetPath);
  validateSandboxGrantPath(normalized);
  if (mode === "rw" && isPathMasked(normalized, [...DEFAULT_MASKED_PATTERNS, ...(profile.maskedPaths ?? [])])) {
    throw new Error(`Refusing read-write grant to protected credential path: ${normalized}`);
  }
}

function validateGrantDomain(domain: string): string {
  const normalized = domain.trim().toLowerCase();
  const hostname = normalized.startsWith("*.") ? normalized.slice(2) : normalized;
  const ipv4 = hostname.split(".").length === 4
    && hostname.split(".").every((part) => /^\d+$/.test(part) && Number(part) <= 255);
  const validHostname = hostname === "localhost"
    || ipv4
    || /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(hostname);
  if (!normalized || normalized === "*" || !validHostname) {
    throw new Error(`Invalid network grant domain '${domain}'. Use example.com, localhost, or *.example.com.`);
  }
  return normalized;
}

const sessionBypassApprovals = new Map<string, Set<string>>();

function getBypassApprovals(repoRoot: string, kind: MaskedAuthKind): Set<string> {
  const key = `${repoRoot}::${kind}`;
  let set = sessionBypassApprovals.get(key);
  if (!set) {
    set = new Set();
    sessionBypassApprovals.set(key, set);
  }
  return set;
}

function approvedMaskedPathsForKinds(
  repoRoot: string,
  kinds: Set<MaskedAuthKind>,
  legacyActiveGrantPaths: Set<string>,
): Set<string> {
  const approved = new Set<string>(legacyActiveGrantPaths);
  for (const kind of kinds) {
    for (const path of getMaskedAuthSessionGrants(repoRoot, kind)) approved.add(path);
    for (const path of getMaskedAuthPersistentGrants(repoRoot, kind)) approved.add(path);
  }
  return approved;
}

interface MaskedAuthReadOptions {
  autoAllowWorkspaceDotenvRead?: boolean;
  /** Read-only protected credential paths approved without a prompt; the caller redacts all output. */
  autoApprovedReadPaths?: readonly string[];
  requireSrtBoundary?: boolean;
}

/** Masked paths unmasked without a prompt: workspace dotenv reads and protected credential reads. */
function autoApprovedMaskedPaths(input: {
  command: string;
  cwd: string;
  workspaceDotenvPaths: ReadonlySet<string>;
  options: MaskedAuthReadOptions;
  pinPath: (path: string) => string | null;
}): { dotenv: string[]; all: string[] } {
  const { command, cwd, workspaceDotenvPaths, options, pinPath } = input;
  const dotenv = options.autoAllowWorkspaceDotenvRead && workspaceDotenvPaths.size > 0
    ? [...workspaceDotenvPaths]
    : [];
  const protectedReads = (options.autoApprovedReadPaths ?? [])
    .map(pinPath)
    .filter((path): path is string => path !== null);
  return { dotenv, all: [...dotenv, ...protectedReads] };
}

async function resolveMaskedAuthAccess(
  command: string,
  cwd: string,
  repoRoot: string,
  profile: ResolvedSandboxProfile,
  sandboxConfig: SandboxConfig,
  ctx: ExtensionContext,
  promptWaitTracker: PromptWaitTracker,
  legacyActiveGrantPaths: Set<string>,
  readOptions: MaskedAuthReadOptions = {},
): Promise<{
  blockReason?: string;
  unmaskedPaths: UnmaskedPath[];
  bypass: boolean;
  authDecision?: ResolvedAuthException;
  autoAllowedDotenvPaths?: string[];
  redactOutput?: boolean;
}> {
  const explicitMasked = detectMaskedFileAccess(command, profile, cwd, { includeMissing: true });
  const implicitAuth = await detectImplicitAuthAccess(command, repoRoot);

  let canonicalizationFailed = false;
  const pinPath = (path: string): string | null => {
    try {
      return normalizeGrantPath(path, cwd);
    } catch {
      canonicalizationFailed = true;
      return null;
    }
  };
  const kindByPath = new Map<string, MaskedAuthKind>();
  const explicitMaskedPaths = new Set<string>();
  const workspaceDotenvPaths = new Set<string>();
  for (const path of explicitMasked) {
    const pinnedPath = pinPath(path);
    if (!pinnedPath) continue;
    kindByPath.set(pinnedPath, classifyMaskedPathKind([pinnedPath]));
    explicitMaskedPaths.add(pinnedPath);
    if (
      isSensitiveEnvPath(path, cwd)
      && isWorkspaceLocalFileOperation("read", { path }, repoRoot, { allowWorkspaceEnvRead: true })
    ) {
      workspaceDotenvPaths.add(pinnedPath);
    }
  }
  for (const path of readOptions.autoApprovedReadPaths ?? []) {
    const pinnedPath = pinPath(path);
    if (!pinnedPath) continue;
    if (!kindByPath.has(pinnedPath)) {
      kindByPath.set(pinnedPath, classifyMaskedPathKind([pinnedPath]));
    }
    if (
      isSensitiveEnvPath(pinnedPath, cwd)
      && isWorkspaceLocalFileOperation("read", { path: pinnedPath }, repoRoot, { allowWorkspaceEnvRead: true })
    ) {
      workspaceDotenvPaths.add(pinnedPath);
    }
  }
  if (implicitAuth) {
    for (const path of implicitAuth.candidatePaths) {
      const pinnedPath = pinPath(path);
      if (pinnedPath) kindByPath.set(pinnedPath, implicitAuth.kind);
    }
  }

  if (canonicalizationFailed) {
    return {
      blockReason: "Sandbox: unable to canonicalize protected path; command blocked.",
      unmaskedPaths: [],
      bypass: false,
    };
  }
  if (implicitAuth == null && kindByPath.size === 0) {
    return { unmaskedPaths: [], bypass: false };
  }

  const inferredKind = implicitAuth?.kind ?? (kindByPath.size === 1 ? [...new Set(kindByPath.values())][0] : "generic-secret");
  const authDecision = resolveAuthExceptionPolicy({
    command,
    kind: inferredKind,
    rules: sandboxConfig.authExceptions,
    hasCandidatePaths: kindByPath.size > 0,
    needsSocketFallback: implicitAuth?.needsSocketFallback ?? false,
  });
  const autoApproved = authDecision.strategy === "ask-unmask"
    && authDecision.matchedRule === undefined
    ? autoApprovedMaskedPaths({ command, cwd, workspaceDotenvPaths, options: readOptions, pinPath })
    : { dotenv: [], all: [] };
  const autoAllowedDotenvPaths = autoApproved.dotenv;

  if (authDecision.strategy === "deny") {
    return {
      blockReason: `Sandbox: ${authDecision.reason}`,
      unmaskedPaths: [],
      bypass: false,
      authDecision,
    };
  }

  if (
    authDecision.strategy === "ask-bypass"
    && (
      explicitMaskedPaths.size > 0
      || (await protectedBashReadPaths(command, cwd)).length > 0
    )
  ) {
    return {
      blockReason: "Sandbox: protected paths cannot be combined with unsandboxed authentication; split the command.",
      unmaskedPaths: [],
      bypass: false,
      authDecision,
    };
  }

  if (authDecision.strategy === "ask-bypass" && readOptions.requireSrtBoundary) {
    return {
      blockReason: "Sandbox: this command requires the SRT read-only boundary; authentication bypass blocked.",
      unmaskedPaths: [],
      bypass: false,
      authDecision,
    };
  }

  if (authDecision.strategy === "ask-bypass") {
    const approvals = getBypassApprovals(repoRoot, authDecision.kind);
    if (approvals.has(authDecision.approvalKey)) {
      return { unmaskedPaths: [], bypass: true, authDecision };
    }
    const promptResult = await promptSandboxGrant(ctx, {
      change: {
        type: "auth-bypass",
        values: [authDecision.kind],
        description: `The command "${command}" needs ${authDecision.kind} access that is safer or more reliable outside the sandbox. Approving will run this command outside sandbox protections for the selected duration.`,
        authKind: authDecision.kind,
      },
      command,
      promptWaitTracker,
      allowPersistentScopes: false,
    });
    if (promptResult.action === "deny") {
      return {
        blockReason: `Sandbox: ${authDecision.reason} User denied unsandboxed execution.`,
        unmaskedPaths: [],
        bypass: false,
        authDecision,
      };
    }
    if (promptResult.duration === "session") {
      approvals.add(authDecision.approvalKey);
    }
    return { unmaskedPaths: [], bypass: true, authDecision };
  }

  const kinds = new Set<MaskedAuthKind>(kindByPath.values());
  if (kinds.size === 0) kinds.add(authDecision.kind);
  const approved = approvedMaskedPathsForKinds(repoRoot, kinds, legacyActiveGrantPaths);
  if (implicitAuth?.kind === "docker-auth") {
    for (const [path, kind] of kindByPath) {
      if (kind === "docker-auth") approved.add(path);
    }
  }
  for (const path of autoApproved.all) approved.add(path);
  const pendingPaths = [...kindByPath.keys()].filter((path) => !approved.has(path));

  const unmaskedPaths: UnmaskedPath[] = [...kindByPath.keys()]
    .filter((path) => approved.has(path))
    .map((path) => ({ path, writable: false }));
  const shouldRedactExplicitMaskedOutput = () => unmaskedPaths.some(({ path }) =>
    explicitMaskedPaths.has(path) && !workspaceDotenvPaths.has(path));

  if (pendingPaths.length === 0) {
    return {
      unmaskedPaths,
      bypass: false,
      authDecision,
      autoAllowedDotenvPaths,
      redactOutput: shouldRedactExplicitMaskedOutput(),
    };
  }

  const kind = authDecision.kind;
  const promptResult = await promptSandboxGrant(ctx, {
    change: {
      type: "path",
      mode: "ro",
      values: pendingPaths,
      description: formatMaskedAccessSuggestion(command, pendingPaths, kind),
      authKind: kind,
    },
    command,
    promptWaitTracker,
    allowPersistentScopes: false,
  });

  if (promptResult.action === "deny") {
    return {
      blockReason: `Sandbox: ${formatMaskedAccessSuggestion(command, pendingPaths, kind)} User denied access.`,
      unmaskedPaths: [],
      bypass: false,
      authDecision,
    };
  }

  for (const path of pendingPaths) {
    unmaskedPaths.push({ path, writable: false });
    if (promptResult.duration === "session") {
      addMaskedAuthSessionGrant(repoRoot, kindByPath.get(path) ?? kind, path);
    } else if (promptResult.duration === "always") {
      const pathKind = kindByPath.get(path) ?? kind;
      addMaskedAuthSessionGrant(repoRoot, pathKind, path);
      addMaskedAuthPersistentGrant(repoRoot, pathKind, path);
    }
  }

  return {
    unmaskedPaths,
    bypass: false,
    authDecision,
    autoAllowedDotenvPaths,
    redactOutput: shouldRedactExplicitMaskedOutput(),
  };
}

// ── Main extension ───────────────────────────────────────────────────────

function isReadOnlyDockerDaemonCommand(command: string): boolean {
  return isDockerCommand(command)
    && isReadOnlyBashDiagnostic(command)
    && command.trim() !== "docker --help";
}

async function resolveBashSandboxAccess(
  command: string,
  cwd: string,
  repoRoot: string,
  config: SandboxConfig,
  bypassed: boolean,
): Promise<{ protectedReadPaths: string[]; sandboxed: boolean; forceSrt: boolean; blockReason?: string }> {
  const protectedReadPaths = await protectedBashReadPaths(command, cwd);
  const hasProtectedRead = protectedReadPaths.length > 0;
  const dockerRequiresSrt = config.enabled && isReadOnlyDockerDaemonCommand(command);
  const forceSrt = hasProtectedRead || dockerRequiresSrt;
  const sandboxed = config.enabled
    && config.backend === "srt"
    && (forceSrt || !bypassed);

  if (!sandboxed) {
    if (forceSrt) {
      return {
        protectedReadPaths,
        sandboxed,
        forceSrt,
        blockReason: hasProtectedRead
          ? "Sandbox: credential access requires the SRT read-only boundary; command blocked."
          : "Sandbox: Docker diagnostics require the SRT read-only boundary; command blocked.",
      };
    }
    try {
      const implicitAuth = await detectImplicitAuthAccess(command, repoRoot);
      if (implicitAuth && !isReadOnlyBashDiagnostic(command)) {
        return {
          protectedReadPaths,
          sandboxed,
          forceSrt,
          blockReason: "Sandbox: implicit credential access requires the SRT read-only boundary; command blocked.",
        };
      }
    } catch {
      return {
        protectedReadPaths,
        sandboxed,
        forceSrt,
        blockReason: "Sandbox: unable to verify implicit credential access; command blocked.",
      };
    }
  }

  return { protectedReadPaths, sandboxed, forceSrt };
}

function configWithSrtBoundary(config: SandboxConfig, forceSrt: boolean): SandboxConfig {
  return forceSrt ? { ...config, bypassCommands: [] } : config;
}

export default function piPermissionSystemExtension(pi: ExtensionAPI): void {
  // ── Upstream setup (identical to original index.ts) ───────────────────
  const runtime = createExtensionRuntime();
  const hostCapabilityBypassApprovals = new Set<string>();
  const resolveHostCapabilityDecision = async (
    command: string,
    ctx: ExtensionContext,
  ): Promise<"allowed" | "denied" | "not-needed"> => {
    if (!isHostCapabilityBootstrapCommand(command)) return "not-needed";
    if (defaultSrtStatus(null).available) return "not-needed";
    const approvalKey = `${resolveRepoRoot(ctx.cwd)}::host-toolchain`;
    if (hostCapabilityBypassApprovals.has(approvalKey)) return "allowed";
    const promptResult = await promptSandboxGrant(ctx, {
      change: {
        type: "host-bypass",
        values: ["host-toolchain"],
        description:
          `The direct command "${command}" requires host toolchain capability, `
          + "but the SRT sandbox is unavailable. Approving runs it outside sandbox protections for this session or once.",
      },
      command,
      promptWaitTracker,
      allowPersistentScopes: false,
    });
    if (promptResult.action === "deny") return "denied";
    if (promptResult.duration === "session") {
      hostCapabilityBypassApprovals.add(approvalKey);
    }
    return "allowed";
  };
  const yoloAutoSocketPath =
    process.env.PI_SENTINEL_YOLO_AUTO_SOCKET?.trim()
    || join(runtime.agentDir, "runtime", "pi-sentinel", "yolo-auto.sock");
  const yoloAutoClient = new YoloAutoClient(
    createUnixSocketWorkerTransport(yoloAutoSocketPath),
    { expectedBuildId: YOLO_AUTO_BUILD_ID },
  );
  const promptWaitTracker = new PromptWaitTracker(pi.events);
  const clipboardTempCleanup = createPiClipboardTempCleanup();
  const pendingSrtWraps = new Map<string, {
    cleanup?: () => void;
    helperPayloadBytes?: number;
    rawCommandBytes?: number;
    dotenvPaths?: string[];
    redactOutput?: boolean;
  }>();

  refreshExtensionConfig(runtime);
  let yoloAutoWorker: YoloAutoWorkerHandle | undefined;
  let yoloAutoWorkerStart: Promise<YoloAutoWorkerHandle> | undefined = runtime.config.mode === "yolo-auto"
    ? startYoloAutoWorker(
      yoloAutoSocketPath,
      runtime.agentDir,
      runtime.writeDebugLog.bind(runtime),
    )
    : undefined;
  const adoptYoloAutoWorker = (worker: YoloAutoWorkerHandle): void => {
    yoloAutoWorker = worker;
    const child = worker.process;
    if (!child || child.exitCode !== null) {
      if (child?.exitCode !== null) yoloAutoWorker = undefined;
      return;
    }
    const clearWorker = (): void => {
      if (yoloAutoWorker?.process === child) yoloAutoWorker = undefined;
    };
    child.once("error", clearWorker);
    child.once("exit", clearWorker);
  };
  const startOrAdoptYoloAutoWorker = async (): Promise<void> => {
    if (!yoloAutoWorkerStart && !yoloAutoWorker) {
      yoloAutoWorkerStart = startYoloAutoWorker(
        yoloAutoSocketPath,
        runtime.agentDir,
        runtime.writeDebugLog.bind(runtime),
      );
    }
    const starting = yoloAutoWorkerStart;
    if (starting) {
      try {
        adoptYoloAutoWorker(await starting);
      } finally {
        if (yoloAutoWorkerStart === starting) yoloAutoWorkerStart = undefined;
      }
    }
    await yoloAutoWorker?.startupSignal;
  };
  let yoloAutoReadiness: Promise<void> | undefined;
  const ensureYoloAutoWorkerReady = async (): Promise<void> => {
    if (runtime.config.mode !== "yolo-auto") return;
    if (yoloAutoReadiness) return yoloAutoReadiness;

    const readiness = (async () => {
      await startOrAdoptYoloAutoWorker();
      try {
        await waitForWorkerStartup(
          () => yoloAutoClient.waitUntilReady(),
          async () => {
            yoloAutoWorker = undefined;
            yoloAutoWorkerStart = undefined;
            await startOrAdoptYoloAutoWorker();
          },
        );
      } catch (error) {
        runtime.writeDebugLog("yolo_auto.worker_unavailable", {
          reason: error instanceof YoloAutoBuildMismatchError ? "build_mismatch" : "handshake_failed",
        });
        throw error;
      }
    })();
    yoloAutoReadiness = readiness;
    try {
      await readiness;
    } finally {
      if (yoloAutoReadiness === readiness) yoloAutoReadiness = undefined;
    }
  };

  let decisionStore: DecisionStore | undefined;
  const getDecisionStore = (): DecisionStore => {
    decisionStore ??= openDecisionStore(
      join(getGlobalConfigDir(runtime.agentDir), "decision-store", "decisions.db"),
    );
    return decisionStore;
  };

  const yoloAutoEvaluator = new YoloAutoEvaluator({
    client: yoloAutoClient,
    waitForStartup: ensureYoloAutoWorkerReady,
    writeReviewLog: runtime.writeReviewLog.bind(runtime),
    writeDebugLog: runtime.writeDebugLog.bind(runtime),
    writeCalibrationLog: (record) => writeYoloAutoCalibrationRecord(runtime.agentDir, record),
    recordEvaluation: (row) => getDecisionStore().recordEvaluation(row),
    summarizeNeighbours: (query) => summarizeNeighbours(
      getDecisionStore().listLabelled(query.toolName, query.operation, query.now - NEIGHBOUR_WINDOW_MS),
      query,
    ),
    scoreRequest: (query) => scoreWithHistory(
      getDecisionStore()
        .listLabelled(query.toolName, query.operation, query.now - NEIGHBOUR_WINDOW_MS)
        // Audit approvals add no allow evidence, matching the neighbour summary.
        .filter((row) => row.scope === query.scope && (row.humanAction === "deny" || !row.audit))
        .map((row) => ({ features: row.features, label: row.humanAction === "deny" ? 0 : 1 })),
      query.features,
    ),
  });

  const prompter = new PermissionPrompter({
    promptWaitTracker,
    recordHumanDecision: (evaluationId, action, ts) => {
      getDecisionStore().recordHumanDecision(evaluationId, action, ts);
    },
    getConfig: () => runtime.config,
    writeReviewLog: runtime.writeReviewLog.bind(runtime),
    writeDebugLog: runtime.writeDebugLog.bind(runtime),
    subagentSessionsDir: runtime.subagentSessionsDir,
    forwardingDir: runtime.forwardingDir,
    resolveFallbackTargetSessionId: (ctx) =>
      resolveInteractiveSessionFallback(runtime, ctx.cwd),
    yoloAutoClient,
    yoloAutoEvaluator,
    waitForYoloAutoStartup: ensureYoloAutoWorkerReady,
    requestPermissionDecisionFromUi,
  });

  const forwardingDeps: PermissionForwardingDeps = {
    forwardingDir: runtime.forwardingDir,
    subagentSessionsDir: runtime.subagentSessionsDir,
    promptWaitTracker,
    logger: {
      writeReviewLog: runtime.writeReviewLog.bind(runtime),
      writeDebugLog: runtime.writeDebugLog.bind(runtime),
    },
    writeReviewLog: runtime.writeReviewLog.bind(runtime),
    requestPermissionDecisionFromUi,
    shouldAutoApprove: (request) =>
      shouldAutoApproveForwardedPermissionRequest(runtime.config, {
        toolName: request.toolName,
        command: request.command,
        forcePromptInYolo: request.forcePromptInYolo,
      }),
    resolveFallbackTargetSessionId: (ctx) =>
      resolveInteractiveSessionFallback(runtime, ctx.cwd),

  };

  const session = new PermissionSession(
    runtime,
    createSessionLogger(runtime),
    new ForwardingManager(runtime.subagentSessionsDir, forwardingDeps),
    {
      refreshExtensionConfig: (ctx) => refreshExtensionConfig(runtime, ctx),
      logResolvedConfigPaths: () => logResolvedConfigPaths(runtime),
      getConfig: () => runtime.config,
      persistPermissionRule: (cwd, scope, surface, pattern) =>
        persistPermissionRule(runtime, cwd, scope, surface, pattern),
      canRequestPermissionConfirmation: (ctx, details) => {
        const fallbackTargetSessionId = resolveInteractiveSessionFallback(
          runtime,
          ctx.cwd,
        );
        return canResolveAskPermissionRequest({
          config: runtime.config,
          hasUI: ctx.hasUI,
          isSubagent:
            isSubagentExecutionContext(ctx, runtime.subagentSessionsDir) ||
            (!ctx.hasUI && Boolean(fallbackTargetSessionId)),
          toolName: details?.toolName,
          command: details?.command,
          forcePromptInYolo: details?.forcePromptInYolo,
        });
      },
      promptPermission: (ctx, details) => prompter.prompt(ctx, details),

    },
  );

  registerPermissionSystemCommand(pi, {
    getConfig: () => runtime.config,
    setConfig: (next, ctx, modeWasExplicitlySelected, modeScope) =>
      saveExtensionConfig(runtime, next, ctx, modeWasExplicitlySelected, modeScope),
    resetConfig: (ctx) => resetExtensionConfig(runtime, ctx),
    getModeLayers: (cwd) => getModeLayers(runtime, runtime.runtimeContext?.cwd ?? cwd),
    getConfigPath: (cwd) =>
      [
        `bundled: ${getBundledConfigPath(EXTENSION_ROOT)}`,
        `global: ${getGlobalConfigPath(runtime.agentDir)}`,
        `project: ${cwd ? getProjectConfigPath(cwd) : "(none)"}`,
        `legacy project: ${cwd ? getLegacyProjectExtensionConfigPath(cwd) : "(none)"}`,
        `legacy policy: ${cwd ? getLegacyProjectPolicyPath(cwd) : "(none)"}`,
      ].join("\n"),
    getComposedRules: () =>
      runtime.permissionManager.getComposedConfigRules(
        runtime.lastKnownActiveAgentName ?? undefined,
      ),
    getSandboxEnabled: () => normalizeSandboxConfig(loadConfig().sandbox).enabled,
    setSandboxEnabled: (enabled, ctx) => {
      if (!saveSandboxEnabled(runtime, enabled, ctx)) return;
      sandboxRuntime.reloadConfig();
      ctx.ui.notify(`Bash sandbox ${enabled ? "on" : "off"} (global).`, "info");
    },
    getYoloAutoStatus: () => {
      const status = yoloAutoClient.getStatus();
      return status.state === "fallback"
        ? `yoloAutoWorker=fallback:${status.reason}`
        : `yoloAutoWorker=${status.state}`;
    },
  });

  const rpcHandles = registerPermissionRpcHandlers(pi.events, {
    promptWaitTracker,
    getPermissionManager: () => runtime.permissionManager,
    getSessionRules: () => runtime.sessionRules.getRuleset(),
    getRuntimeContext: () => runtime.runtimeContext,
    requestPermissionDecisionFromUi,
    writeReviewLog: runtime.writeReviewLog.bind(runtime),
    writeDebugLog: runtime.writeDebugLog.bind(runtime),
  });

  const permissionsService: PermissionsService = {
    checkPermission(surface, value, agentName) {
      const input = buildInputForSurface(surface, value);
      const sessionRules = runtime.sessionRules.getRuleset();
      return runtime.permissionManager.checkPermission(
        surface,
        input,
        agentName,
        sessionRules,
      );
    },
  };
  publishPermissionsService(permissionsService);

  emitReadyEvent(pi.events);

  pi.events.on("pi-sentinel:set-session-mode", (data) => {
    applySessionModeEvent(runtime, data);
  });

  const toolRegistry = {
    getAll: () => pi.getAllTools(),
    setActive: (names: string[]) => pi.setActiveTools(names),
  };

  const lifecycle = new SessionLifecycleHandler(session, () => {
    rpcHandles.unsubCheck();
    rpcHandles.unsubPrompt();
    unpublishPermissionsService();
  });
  const agentPrep = new AgentPrepHandler(session, toolRegistry);
  const gates = new PermissionGateHandler(session, pi.events, toolRegistry);

  type PersistentGrantRecord =
    | { kind: "network"; configPath: string; value: string; scope: PersistentApprovalScope }
    | { kind: "sandbox-network"; configPath: string; scope: PersistentApprovalScope }
    | { kind: "path"; configPath: string; value: string; scope: PersistentApprovalScope };
  const persistentGrantRecords = new Map<string, PersistentGrantRecord>();
  let sandboxAuthorizationUnavailable = false;

  type ConfigSnapshot = {
    path: string;
    existed: boolean;
    config: Record<string, unknown>;
  };
  const snapshotConfigs = (paths: Iterable<string>): ConfigSnapshot[] => [...new Set(paths)].map((configPath) => ({
    path: configPath,
    existed: existsSync(configPath),
    config: readConfigFile(configPath),
  }));
  const restoreConfigs = (snapshots: ConfigSnapshot[], workspaceRoot?: string): void => {
    let firstError: Error | undefined;
    for (const snapshot of snapshots) {
      try {
        if (snapshot.existed) {
          if (!writeConfigFile(snapshot.path, snapshot.config, workspaceRoot)) {
            throw new Error(`Failed to restore config at '${snapshot.path}'.`);
          }
        } else if (existsSync(snapshot.path)) {
          const stat = lstatSync(snapshot.path);
          if (stat.isSymbolicLink() || !stat.isFile()) {
            throw new Error(`Failed to remove unexpected config at '${snapshot.path}'.`);
          }
          unlinkSync(snapshot.path);
        }
      } catch (error) {
        firstError ??= error instanceof Error ? error : new Error(String(error));
      }
    }
    if (firstError) throw firstError;
  };
  const rollbackSandboxChanges = (
    policyManager: SandboxPolicyManager,
    grants: Grant[],
    snapshots: ConfigSnapshot[],
    workspaceRoot?: string,
  ): void => {
    for (const grant of grants) policyManager.revokeGrant(grant.id);
    try {
      restoreConfigs(snapshots, workspaceRoot);
      if (snapshots.length > 0) sandboxRuntime.reloadConfig();
      for (const grant of grants) persistentGrantRecords.delete(grant.id);
    } catch {
      sandboxAuthorizationUnavailable = true;
    }
  };
  const revokeRecordedGrants = (policyManager: SandboxPolicyManager, paths: Set<string>): void => {
    for (const [grantId, record] of persistentGrantRecords) {
      if (record.kind === "sandbox-network" && paths.has(record.configPath)) {
        policyManager.revokeGrant(grantId);
        persistentGrantRecords.delete(grantId);
      }
    }
  };
  const persistNetworkGrantTransaction = (
    policyManager: SandboxPolicyManager,
    cwd: string,
    domains: readonly string[],
    scope: PersistentApprovalScope,
    state: "allow" | "deny" = "allow",
  ): void => {
    const configPath = getSafeScopedConfigPath(scope, cwd);
    const workspaceRoot = scope === "workspace" ? cwd : undefined;
    const snapshots = snapshotConfigs([configPath]);
    try {
      for (const domain of domains) persistScopedNetworkGrant(scope, cwd, domain, state);
      sandboxRuntime.reloadConfig();
    } catch (error) {
      rollbackSandboxChanges(policyManager, [], snapshots, workspaceRoot);
      throw error;
    }
  };

  let activeWorkspaceCwd = process.cwd();
  pi.on("session_start", (event, ctx) => {
    clipboardTempCleanup.reset();
    activeWorkspaceCwd = ctx.cwd;
    sandboxAuthorizationUnavailable = false;
    promptWaitTracker.clear(runtime.runtimeContext ?? undefined);
    sessionBypassApprovals.clear();
    hostCapabilityBypassApprovals.clear();
    clearSessionNetworkApprovals();
    clearMaskedAuthSessionGrants();
    sandboxRuntime.clearGrants();
    runtime.sessionMode = undefined;
    recordInteractiveSession(runtime, ctx);
    return lifecycle.handleSessionStart(event, ctx);
  });
  pi.on("resources_discover", (event) =>
    lifecycle.handleResourcesDiscover(event),
  );
  pi.on("session_shutdown", () => {
    yoloAutoClient.close();
    clipboardTempCleanup.cleanup();
    promptWaitTracker.clear(runtime.runtimeContext ?? undefined);
    sessionBypassApprovals.clear();
    hostCapabilityBypassApprovals.clear();
    clearSessionNetworkApprovals();
    clearMaskedAuthSessionGrants();
    sandboxRuntime.dispose();
    return lifecycle.handleSessionShutdown();
  });
  pi.on("before_agent_start", (event, ctx) => agentPrep.handle(event, ctx));
  pi.on("input", (event, ctx) => {
    clipboardTempCleanup.trackText(event.text);
    if (event.source === "interactive") {
      clipboardTempCleanup.trackInteractiveText(event.text);
    }
    return gates.handleInput(event, ctx);
  });
  // NOTE: tool_call and user_bash are handled below with our additions

  // ── Our additions: lazy config/runtime, commands ─────────────────────
  const sandboxRuntime = createSandboxRuntimeLoader({
    loadConfig,
    normalizeSandboxConfig,
    createPolicyManager: (cfg) => new SandboxPolicyManager(cfg),
    createBackend: () => createSrtBackend({ helperPath: () => defaultSrtHelperPath(null) }),
  });

  const getNetworkConfig = (cwd?: string): DomainGateConfig | undefined =>
    loadConfig(cwd).network;
  const getSandboxConfig = (cwd?: string): SandboxConfig => {
    if (sandboxAuthorizationUnavailable) {
      throw new Error("Sandbox authorization state unavailable.");
    }
    return normalizeSandboxConfig(loadConfig(cwd).sandbox);
  };
  const getPolicyManager = (): SandboxPolicyManager =>
    sandboxRuntime.getRuntime().policyManager;
  const getSandboxBackend = (_cwd?: string) => createSrtBackend({
    helperPath: () => defaultSrtHelperPath(null),
    onE2Big: (details) => runtime.writeDebugLog("spawn.e2big", details),
  });

  /** Configured bypass patterns, plus trusted Pi agent scripts which always run on the host. */
  function bypassesSandbox(command: string, cwd: string): boolean {
    return shouldBypassSandboxCommand(command, getSandboxConfig(cwd).bypassCommands ?? [])
      || matchTrustedPiRequest("bash", { command }, cwd, session.getTrustedPiDirs())?.kind === "script";
  }

  function getEffectiveSandboxConfig(cwd: string): SandboxConfig {
    const config = getSandboxConfig(cwd);
    return {
      ...config,
      infrastructureReadPaths: [
        ...session.getInfrastructureDirs(),
        ...session.getInfrastructureReadPaths(),
      ],
    };
  }

  const rememberPersistentGrant = (grant: Grant, record: PersistentGrantRecord): void => {
    persistentGrantRecords.set(grant.id, record);
  };

  type PersistentSandboxNetworkRecord = {
    id: string;
    scope: PersistentApprovalScope;
    configPaths: string[];
  };
  const getPersistentSandboxNetworkRecords = (cwd: string): PersistentSandboxNetworkRecord[] => {
    const scoped = loadMergedScopedConfig(getAgentDir(), cwd);
    const hasCapability = (config: Record<string, unknown>): boolean => {
      const sandbox = config.sandbox;
      return Boolean(
        sandbox &&
        typeof sandbox === "object" &&
        !Array.isArray(sandbox) &&
        (sandbox as { network?: unknown }).network === true,
      );
    };
    const hasCapabilityAt = (configPath: string): boolean => {
      try {
        return hasCapability(readConfigFile(configPath));
      } catch {
        return false;
      }
    };
    const records: PersistentSandboxNetworkRecord[] = [];
    const globalPaths = [
      scoped.globalPath,
      getLegacyGlobalPolicyPath(getAgentDir()),
    ].filter((configPath, index, paths) => paths.indexOf(configPath) === index && hasCapabilityAt(configPath));
    if (globalPaths.length > 0) {
      records.push({
        id: "sandbox-network-global",
        scope: "global",
        configPaths: globalPaths,
      });
    }
    const workspacePaths = [
      getProjectConfigPath(cwd),
      getLegacyProjectConfigPath(cwd),
      getLegacyProjectExtensionConfigPath(cwd),
      getLegacyProjectPolicyPath(cwd),
    ]
      .filter((configPath, index, paths) => paths.indexOf(configPath) === index)
      .filter((configPath) => {
        resolveConfinedConfigPath(configPath, cwd);
        return hasCapabilityAt(configPath);
      });
    if (workspacePaths.length > 0) {
      records.push({
        id: "sandbox-network-workspace",
        scope: "workspace",
        configPaths: workspacePaths,
      });
    }
    return records;
  };

  function revokeSandboxNetworkCapability(
    policyManager: SandboxPolicyManager,
    configPaths: Iterable<string>,
    scope: PersistentApprovalScope,
    cwd: string,
  ): void {
    const paths = new Set(configPaths);
    const workspaceRoot = scope === "workspace" ? cwd : undefined;
    const snapshots = snapshotConfigs(paths);
    try {
      for (const configPath of paths) {
        removeSandboxNetworkGrantFromConfig(configPath, workspaceRoot);
      }
    } catch (error) {
      rollbackSandboxChanges(policyManager, [], snapshots, workspaceRoot);
      throw error;
    }

    try {
      sandboxRuntime.reloadConfig();
    } catch (error) {
      try {
        restoreConfigs(snapshots, workspaceRoot);
        sandboxRuntime.reloadConfig();
      } catch {
        sandboxAuthorizationUnavailable = true;
        revokeRecordedGrants(policyManager, paths);
      }
      throw error;
    }
    revokeRecordedGrants(policyManager, paths);
  }

  // ── Register our commands ────────────────────────────────────────────
  registerDomainGateCommand(pi, getNetworkConfig);

  type SandboxCompletion = { value: string; label: string; description?: string };
  const completeSandboxGrant = (argumentPrefix: string): SandboxCompletion[] => {
    const hasTrailingWhitespace = /\s$/.test(argumentPrefix);
    const prefix = argumentPrefix.trimEnd();
    if (!prefix) {
      return [
        { value: "path", label: "path", description: "Grant filesystem access" },
        { value: "network", label: "network", description: "Grant network access" },
      ];
    }

    const parts = prefix.split(/\s+/);
    const subcommand = parts[0];
    if (subcommand !== "path" && subcommand !== "network") return [];
    const last = parts.at(-1) ?? "";
    const flags = subcommand === "path" ? ["--ro", "--rw", "--ttl"] : ["--domain", "--ttl"];
    const usedFlags = new Set(parts.filter((part) => flags.includes(part)));
    if (hasTrailingWhitespace) {
      return flags
        .filter((flag) => !usedFlags.has(flag))
        .map((flag) => ({ value: `${argumentPrefix}${flag}`, label: flag }));
    }
    if (!last.startsWith("--")) return [];
    const stem = prefix.slice(0, prefix.length - last.length);
    return flags
      .filter((flag) => !usedFlags.has(flag) && flag.startsWith(last))
      .map((flag) => ({ value: `${stem}${flag}`, label: flag }));
  };

  pi.registerCommand("sandbox-status", {
    description: "Show sandbox status and active profile",
    handler: async (_args: string, ctx: ExtensionContext) => {
      const sc = getSandboxConfig(ctx.cwd);
      if (!sc.enabled) {
        ctx.ui.notify("Sandbox: disabled", "info");
        return;
      }
      const backendKind = sc.backend ?? "srt";
      const profile = sc.profiles[sc.defaultProfile];
      const grants = getPolicyManager().listGrants();
      const persistentNetwork = getPersistentSandboxNetworkRecords(ctx.cwd);
      const activeGrantIds = new Set(grants.map((grant) => grant.id));
      const activePersistentPaths = new Set(
        [...persistentGrantRecords.entries()]
          .filter(([grantId, record]) => record.kind === "sandbox-network" && activeGrantIds.has(grantId))
          .map(([, record]) => record.configPath),
      );
      const info = [
        `Sandbox: ${sc.enabled ? "enabled" : "disabled"}`,
        `Backend: ${backendKind}`,
        `Profile: ${sc.defaultProfile} (network: ${profile?.network || sc.network ? "on" : "off"})`,
      ];
      const status = defaultSrtStatus(null);
      info.push(`SRT package: ${status.packageAvailable ? "available" : "missing"}`);
      info.push(`Runner: ${status.entrypointPath ?? "not configured"} (${status.entrypointExists ? "exists" : "missing"})`);
      if (status.dependencyChecks.length > 0) {
        info.push(`Dependencies: ${status.dependencyChecks.map((dep) => `${dep.name}=${dep.available ? "ok" : "missing"}`).join(", ")}`);
      }
      info.push(`Active grants: ${grants.length}`);
      if (status.error) info.push(`Error: ${status.error}`);
      for (const g of grants) {
        const expires = g.expiresAt ? `expires ${g.expiresAt.toISOString()}` : "session end";
        info.push(`  ${g.id}: ${g.type} ${g.value}${g.mode ? ` (${g.mode})` : ""} [${expires}]`);
      }
      for (const [grantId, record] of persistentGrantRecords) {
        if (activeGrantIds.has(grantId) || record.kind === "sandbox-network") continue;
        info.push(`  ${grantId}: ${record.kind} ${record.value} [persistent]`);
      }
      for (const record of persistentNetwork) {
        if (!record.configPaths.some((configPath) => activePersistentPaths.has(configPath))) {
          info.push(`  ${record.id}: network capability (${record.scope}) [persistent]`);
        }
      }
      ctx.ui.notify(info.join("\n"), "info");
    },
  });

  pi.registerCommand("sandbox-grant", {
    description: "Grant sandbox access. Usage: /sandbox-grant path <path> [--ro|--rw] [--ttl 30m] | /sandbox-grant network --domain *.npmjs.org [--ttl 5m]",
    getArgumentCompletions: completeSandboxGrant,
    handler: async (args: string, ctx: ExtensionContext) => {
      const policyManager = getPolicyManager();
      const parts = tokenizeSandboxCommandArgs(args);
      const subcmd = parts[0];

      if (subcmd === "network") {
        let domain: string | undefined;
        let ttl: GrantDuration = "session";
        for (let i = 1; i < parts.length; i++) {
          if (parts[i] === "--domain") {
            if (!parts[i + 1]) throw new Error("Missing value for --domain.");
            domain = validateGrantDomain(parts[++i]!);
          } else if (parts[i] === "--ttl") {
            if (!parts[i + 1]) throw new Error("Missing value for --ttl.");
            ttl = parseTTL(parts[++i]!);
          } else {
            throw new Error(`Unknown sandbox network grant option: ${parts[i]}`);
          }
        }
        if (!domain) throw new Error("Network grant requires --domain example.com or *.example.com.");
        if (ttl === "once") throw new Error("Standalone sandbox grants do not support --ttl once; use --ttl session.");
        let configPath: string | undefined;
        let snapshots: ConfigSnapshot[] = [];
        let grants: Grant[] = [];
        try {
          if (ttl === "always") {
            configPath = getSafeScopedConfigPath("global", ctx.cwd);
            snapshots = snapshotConfigs([configPath]);
            persistScopedSandboxNetworkGrant("global", ctx.cwd);
          }
          grants = policyManager.grantNetwork([domain], {
            duration: ttl,
            projectRoot: resolveRepoRoot(ctx.cwd),
          });
          if (configPath) {
            for (const grant of grants) rememberPersistentGrant(grant, { kind: "sandbox-network", configPath, scope: "global" });
            sandboxRuntime.reloadConfig();
          }
        } catch (error) {
          rollbackSandboxChanges(policyManager, grants, snapshots);
          throw error;
        }
        ctx.ui.notify(`Granted network access to ${domain} (${grants.length} grant(s), ${typeof ttl === "number" ? `${ttl}ms` : ttl})`, "info");
      } else if (subcmd === "path") {
        const rawPath = parts[1];
        if (!rawPath || rawPath.startsWith("--")) {
          throw new Error("Path grant requires a path.");
        }
        let mode: "ro" | "rw" = "ro";
        let ttl: GrantDuration = "session";
        for (let i = 2; i < parts.length; i++) {
          if (parts[i] === "--ro" || parts[i] === "--rw") {
            mode = parts[i] === "--rw" ? "rw" : "ro";
          } else if (parts[i] === "--ttl") {
            if (!parts[i + 1]) throw new Error("Missing value for --ttl.");
            ttl = parseTTL(parts[++i]!);
          } else {
            throw new Error(`Unknown sandbox path grant option: ${parts[i]}`);
          }
        }
        const profile = policyManager.resolveProfile("", ctx.cwd, resolveRepoRoot(ctx.cwd)).profile;
        const requestedPath = expandGrantPath(rawPath, ctx.cwd);
        validateGrantPath(requestedPath, profile, mode);
        const targetPath = normalizeGrantPath(rawPath, ctx.cwd);
        validateGrantPath(targetPath, profile, mode);
        if (ttl === "once") throw new Error("Standalone sandbox grants do not support --ttl once; use --ttl session.");
        if (ttl === "always" && !existsSync(targetPath)) {
          throw new Error("Persistent sandbox path grants require an existing target.");
        }
        let configPath: string | undefined;
        let snapshots: ConfigSnapshot[] = [];
        let grant: Grant | undefined;
        try {
          if (ttl === "always") {
            configPath = getSafeScopedConfigPath("global", ctx.cwd);
            snapshots = snapshotConfigs([configPath]);
            persistScopedSandboxPathGrant("global", ctx.cwd, targetPath, mode);
          }
          grant = policyManager.grantPath(targetPath, mode, {
            duration: ttl,
            projectRoot: resolveRepoRoot(ctx.cwd),
          });
          if (configPath) {
            rememberPersistentGrant(grant, { kind: "path", configPath, value: targetPath, scope: "global" });
            sandboxRuntime.reloadConfig();
          }
        } catch (error) {
          rollbackSandboxChanges(policyManager, grant ? [grant] : [], snapshots);
          throw error;
        }
        if (!grant) throw new Error("Sandbox path grant was not created.");
        ctx.ui.notify(`Granted ${mode} access to ${targetPath} (${grant.id})`, "info");
      } else {
        ctx.ui.notify("Usage: /sandbox-grant network --domain example.com [--ttl 30m] | /sandbox-grant path <path> [--ro|--rw] [--ttl 30m]", "warning");
      }
    },
  });

  pi.registerCommand("sandbox-revoke", {
    description: "Revoke a sandbox grant. Usage: /sandbox-revoke <grant-id>",
    getArgumentCompletions: (argumentPrefix: string): SandboxCompletion[] => {
      const query = argumentPrefix.trim();
      const grantIds = getPolicyManager()
        .listGrants()
        .filter((grant) => grant.id.startsWith(query))
        .map((grant) => ({ value: grant.id, label: grant.id, description: `${grant.type}: ${grant.value}` }));
      const activeIds = new Set(grantIds.map((grant) => grant.value));
      const persistedIds = [...persistentGrantRecords.entries()]
        .filter(([id]) => id.startsWith(query) && !activeIds.has(id))
        .map(([id, record]) => ({
          value: id,
          label: id,
          description: record.kind === "path" ? `path: ${record.value}` : record.kind,
        }));
      const persistentIds = getPersistentSandboxNetworkRecords(activeWorkspaceCwd)
        .filter((record) => record.id.startsWith(query))
        .map((record) => ({ value: record.id, label: record.id, description: `network capability: ${record.scope}` }));
      return [...grantIds, ...persistedIds, ...persistentIds];
    },
    handler: async (args: string, ctx: ExtensionContext) => {
      const policyManager = getPolicyManager();
      const id = args.trim();
      if (!id) {
        ctx.ui.notify("Usage: /sandbox-revoke <grant-id>", "warning");
        return;
      }
      const persistedSandboxNetwork = getPersistentSandboxNetworkRecords(ctx.cwd)
        .find((record) => record.id === id);
      if (persistedSandboxNetwork) {
        revokeSandboxNetworkCapability(
          policyManager,
          persistedSandboxNetwork.configPaths,
          persistedSandboxNetwork.scope,
          ctx.cwd,
        );
        ctx.ui.notify(`Revoked grant ${id}`, "info");
        return;
      }
      const persistent = persistentGrantRecords.get(id);
      if (persistent?.kind === "sandbox-network") {
        revokeSandboxNetworkCapability(
          policyManager,
          [persistent.configPath],
          persistent.scope,
          ctx.cwd,
        );
        ctx.ui.notify(`Revoked grant ${id}`, "info");
        return;
      }
      if (persistent) {
        const workspaceRoot = persistent.scope === "workspace" ? ctx.cwd : undefined;
        const snapshots = snapshotConfigs([persistent.configPath]);
        try {
          if (persistent.kind === "network") {
            removeNetworkGrantFromConfig(
              persistent.configPath,
              persistent.value,
              workspaceRoot,
            );
          } else {
            removeSandboxPathGrantFromConfig(
              persistent.configPath,
              persistent.value,
              workspaceRoot,
            );
          }
          sandboxRuntime.reloadConfig();
        } catch (error) {
          try {
            restoreConfigs(snapshots, workspaceRoot);
            sandboxRuntime.reloadConfig();
          } catch {
            // Keep live grant and record when durable state cannot be restored.
          }
          throw error;
        }
        policyManager.revokeGrant(id);
        persistentGrantRecords.delete(id);
        ctx.ui.notify(`Revoked grant ${id}`, "info");
        return;
      }
      const revoked = policyManager.revokeGrant(id);
      ctx.ui.notify(revoked ? `Revoked grant ${id}` : `Grant ${id} not found`, revoked ? "info" : "warning");
    },
  });

  // ── Augmented tool_call handler (upstream + our gates) ────────────────
  pi.on("tool_call", (event: unknown, ctx: ExtensionContext) => (async () => {
    activeWorkspaceCwd = ctx.cwd;
    const e = event as { toolCallId?: string; toolName?: string; input?: unknown };
    clipboardTempCleanup.trackValue(e.input);
    let sc: SandboxConfig;
    let policyManager: SandboxPolicyManager;
    try {
      sc = getSandboxConfig(ctx.cwd);
      policyManager = getPolicyManager();
    } catch {
      return { block: true, reason: "Permission config unavailable; command blocked." };
    }

    // 1. Network domain gate (our addition — runs before upstream gates)
    let networkResult: Awaited<ReturnType<typeof handleNetworkToolCall>>;
    try {
      networkResult = await handleNetworkToolCall(
        e as Parameters<typeof handleNetworkToolCall>[0],
        ctx,
        {
          getNetworkConfig,
          getAgentDir: getAgentDir,
          autoApproveAsk: () => runtime.config.mode === "yolo",
          promptWaitTracker,
          persistNetworkGrants: (domains, scope, state) =>
            persistNetworkGrantTransaction(policyManager, ctx.cwd, domains, scope, state),
        },
      );
    } catch {
      return { block: true, reason: "Permission authorization failed; command blocked." };
    }
    if (networkResult?.block) {
      return { block: true, reason: networkResult.reason };
    }
    const approvedNetworkDomains = [
      ...getSessionNetworkApprovals(),
      ...(networkResult?.approvedDomains ?? []),
    ];

    const bashCommand = e.toolName === "bash"
      ? (e.input as { command?: unknown })?.command
      : undefined;
    let protectedReadPaths: string[] = [];
    let sandboxedBash = false;
    let forceSrtForReadOnlyAccess = false;
    if (typeof bashCommand === "string") {
      try {
        const access = await resolveBashSandboxAccess(
          bashCommand,
          ctx.cwd,
          resolveRepoRoot(ctx.cwd),
          sc,
          bypassesSandbox(bashCommand, ctx.cwd),
        );
        if (access.blockReason) return { block: true, reason: access.blockReason };
        protectedReadPaths = access.protectedReadPaths;
        sandboxedBash = access.sandboxed;
        forceSrtForReadOnlyAccess = access.forceSrt;
      } catch {
        return { block: true, reason: "Sandbox: unable to verify credential paths; command blocked." };
      }
    }
    let bashPermissionAlreadyChecked = false;
    if (e.toolName === "bash") {
      try {
        const upstreamResult = await gates.handleToolCall(
          event,
          ctx,
          sandboxedBash,
          protectedReadPaths,
        );
        if (upstreamResult.block) return upstreamResult;
      } catch {
        return { block: true, reason: "Permission authorization failed; command blocked." };
      }
      bashPermissionAlreadyChecked = true;
    }

    // Protected credential reads run without a prompt, so their whole output is redacted.
    const genericProtectedReadPaths = protectedReadPaths.filter((path) =>
      isProtectedCredentialReadPath(path, ctx.cwd));
    let redactProtectedReadOutput = genericProtectedReadPaths.length > 0;
    if (redactProtectedReadOutput && !e.toolCallId) {
      return { block: true, reason: "Unable to track output redaction for protected path read; command blocked." };
    }

    // 2. Sandbox wrapping with dynamic grants (mutates event.input.command)
    if (e.toolName === "bash" && sc.enabled) {
      const command = (e.input as { command?: unknown })?.command;
      if (
        typeof command === "string"
        && sandboxedBash
      ) {
        let effectiveConfig = getEffectiveSandboxConfig(ctx.cwd);
        policyManager.updateConfig(effectiveConfig);
        let resolved = policyManager.resolveProfile(command, ctx.cwd, resolveRepoRoot(ctx.cwd));
        let networkApprovedForInvocation = false;
        const invocationPathGrants: { path: string; mode: "ro" | "rw" }[] = [];

        if (!resolved.canExecute && resolved.requiredChanges) {
          const promptResult = await promptSandboxGrant(ctx, {
            change: resolved.requiredChanges,
            command,
            promptWaitTracker,
          });

          if (promptResult.action === "deny") {
            return {
              block: true,
              reason: `Sandbox: ${resolved.requiredChanges.description}. User denied.`,
            };
          }

          const change = resolved.requiredChanges;
          if (change.type === "network") {
            if (promptResult.duration === "once") {
              networkApprovedForInvocation = true;
            } else {
              let configPath: string | undefined;
              let snapshots: ConfigSnapshot[] = [];
              let grants: Grant[] = [];
              try {
                if (promptResult.duration === "always") {
                  const scope = promptResult.scope ?? "global";
                  configPath = getSafeScopedConfigPath(scope, ctx.cwd);
                  snapshots = snapshotConfigs([configPath]);
                  persistScopedSandboxNetworkGrant(scope, ctx.cwd);
                }
                grants = policyManager.grantNetwork(change.values, {
                  duration: promptResult.duration,
                  projectRoot: resolveRepoRoot(ctx.cwd),
                });
                if (configPath) {
                  for (const grant of grants) {
                    rememberPersistentGrant(grant, { kind: "sandbox-network", configPath, scope: promptResult.scope ?? "global" });
                  }
                  sandboxRuntime.reloadConfig();
                  effectiveConfig = getEffectiveSandboxConfig(ctx.cwd);
                  policyManager.updateConfig(effectiveConfig);
                }
              } catch {
                rollbackSandboxChanges(policyManager, grants, snapshots, promptResult.scope === "workspace" ? ctx.cwd : undefined);
                return {
                  block: true,
                  reason: "Sandbox: failed to persist network approval; command blocked.",
                };
              }
            }
          } else if (change.type === "path") {
            const grants: Grant[] = [];
            let snapshots: ConfigSnapshot[] = [];
            try {
              for (const path of change.values) {
                if (promptResult.duration === "once") {
                  invocationPathGrants.push({ path, mode: change.mode ?? "ro" });
                  continue;
                }
                let configPath: string | undefined;
                if (promptResult.duration === "always") {
                  const scope = promptResult.scope ?? "global";
                  configPath = getSafeScopedConfigPath(scope, ctx.cwd);
                  if (snapshots.length === 0) snapshots = snapshotConfigs([configPath]);
                  persistScopedSandboxPathGrant(scope, ctx.cwd, path, change.mode ?? "ro");
                }
                const grant = policyManager.grantPath(path, change.mode ?? "ro", {
                  duration: promptResult.duration,
                  projectRoot: resolveRepoRoot(ctx.cwd),
                });
                grants.push(grant);
                if (configPath) {
                  rememberPersistentGrant(grant, { kind: "path", configPath, value: path, scope: promptResult.scope ?? "global" });
                  sandboxRuntime.reloadConfig();
                }
              }
            } catch {
              rollbackSandboxChanges(policyManager, grants, snapshots, promptResult.scope === "workspace" ? ctx.cwd : undefined);
              return {
                block: true,
                reason: "Sandbox: failed to persist path approval; command blocked.",
              };
            }
          }

          resolved = policyManager.resolveProfile(
            command,
            ctx.cwd,
            resolveRepoRoot(ctx.cwd),
            { network: networkApprovedForInvocation, pathGrants: invocationPathGrants },
          );
        }

        // Collect unmasked paths from user grants (either from masked-file gate or policy grants)
        // These override the "(masked)" placeholder with real file content
        const unmaskedPaths: UnmaskedPath[] = [];
        let autoAllowedDotenvPaths: string[] = [];

        // Collect active path grant paths to avoid double-prompting
        const activeGrantPaths = new Set(
          policyManager.listGrants(resolveRepoRoot(ctx.cwd))
            .filter((g) => g.type === "path")
            .map((g) => g.value),
        );

        // This covers explicit masked file references (.env, ~/.ssh/id_ed25519, etc.)
        // and implicit auth needs like `git push` / `ssh host` that may not mention
        // the key path on the command line.
        if (sc.enabled) {
          const maskedResolution = await resolveMaskedAuthAccess(
            command,
            ctx.cwd,
            resolveRepoRoot(ctx.cwd),
            resolved.profile,
            effectiveConfig,
            ctx,
            promptWaitTracker,
            activeGrantPaths,
            {
              autoAllowWorkspaceDotenvRead: true,
              autoApprovedReadPaths: protectedReadPaths,
              requireSrtBoundary: forceSrtForReadOnlyAccess && protectedReadPaths.length === 0,
            },
          );
          if (maskedResolution.blockReason) {
            return {
              block: true,
              reason: maskedResolution.blockReason,
            };
          }
          if (maskedResolution.bypass) {
            return undefined;
          }
          redactProtectedReadOutput ||= maskedResolution.redactOutput === true;
          if (redactProtectedReadOutput && !e.toolCallId) {
            return { block: true, reason: "Unable to track output redaction for protected path read; command blocked." };
          }
          if (redactProtectedReadOutput && e.toolCallId) {
            pendingSrtWraps.set(e.toolCallId, { redactOutput: true });
          }
          autoAllowedDotenvPaths = maskedResolution.autoAllowedDotenvPaths ?? [];
          if (autoAllowedDotenvPaths.length > 0 && !e.toolCallId) {
            return { block: true, reason: "Sandbox: unable to track dotenv output redaction; command blocked." };
          }
          for (const entry of maskedResolution.unmaskedPaths) {
            if (!unmaskedPaths.some((u) => u.path === entry.path)) {
              unmaskedPaths.push(entry);
            }
          }
        }

        // 2c. External path gate — detect paths outside sandbox scope and prompt user
        if (sc.enabled) {
          const activeProfile = resolved.profile;
          let externalPaths: Awaited<ReturnType<typeof detectExternalPaths>>;
          let externalWritePaths: Awaited<ReturnType<typeof detectExternalWritePaths>>;
          try {
            externalPaths = await detectExternalPaths(
              command,
              ctx.cwd,
              activeProfile,
              effectiveConfig,
              undefined,
              [...unmaskedPaths.map((entry) => entry.path), ...protectedReadPaths],
            );
            externalWritePaths = await detectExternalWritePaths(
              command, ctx.cwd, activeProfile, effectiveConfig,
            );
          } catch (error) {
            const detail = error instanceof Error && error.message
              ? error.message
              : "invalid external path";
            return { block: true, reason: `Sandbox: ${detail}; command blocked.` };
          }
          const approvalGroups = [
            {
              mode: "ro" as const,
              paths: externalPaths.filter(
                (entry) =>
                  !externalWritePaths.some(
                    (write) =>
                      entry.path === write.path ||
                      (write.isDirectory && isPathWithinDirectory(entry.path, write.path)),
                  ) && !activeGrantPaths.has(entry.path),
              ),
            },
            { mode: "rw" as const, paths: externalWritePaths },
          ];
          let promptedForExternalPaths = false;
          for (const { mode, paths } of approvalGroups) {
            if (paths.length === 0) continue;
            promptedForExternalPaths = true;
            const extPromptResult = await promptSandboxGrant(ctx, {
              change: {
                type: "path",
                mode,
                values: paths.map((entry) => entry.path),
                description: formatExternalPathPrompt(paths, command, mode),
              },
              command,
              promptWaitTracker,
            });

            if (extPromptResult.action === "deny") {
              return {
                block: true,
                reason:
                  "Sandbox: external paths not granted: "
                  + paths.map((entry) => entry.displayPath).join(", "),
              };
            }

            if (extPromptResult.duration === "once") {
              for (const { path } of paths) {
                invocationPathGrants.push({ path, mode });
                activeGrantPaths.add(path);
              }
              continue;
            }

            const grants: Grant[] = [];
            let snapshots: ConfigSnapshot[] = [];
            try {
              const scope = extPromptResult.scope ?? "global";
              for (const entry of paths) {
                const configPath = extPromptResult.duration === "always"
                  ? getSafeScopedConfigPath(scope, ctx.cwd)
                  : undefined;
                if (configPath && snapshots.length === 0) snapshots = snapshotConfigs([configPath]);
                if (extPromptResult.duration === "always") {
                  persistScopedSandboxPathGrant(scope, ctx.cwd, entry.path, mode);
                }
                const grant = policyManager.grantPath(entry.path, mode, {
                  duration: extPromptResult.duration,
                  projectRoot: resolveRepoRoot(ctx.cwd),
                });
                grants.push(grant);
                activeGrantPaths.add(entry.path);
                if (configPath) rememberPersistentGrant(grant, { kind: "path", configPath, value: entry.path, scope });
              }

              if (extPromptResult.duration === "always") {
                effectiveConfig = getEffectiveSandboxConfig(ctx.cwd);
                policyManager.updateConfig(effectiveConfig);
              }
            } catch {
              rollbackSandboxChanges(policyManager, grants, snapshots, extPromptResult.scope === "workspace" ? ctx.cwd : undefined);
              return { block: true, reason: "Sandbox: failed to persist external path approval; command blocked." };
            }
          }

          if (promptedForExternalPaths) {
            resolved = policyManager.resolveProfile(
              command,
              ctx.cwd,
              resolveRepoRoot(ctx.cwd),
              { network: networkApprovedForInvocation, pathGrants: invocationPathGrants },
            );
          }
        }

        // 2d. Secret env handling remains separate from masked auth-file handling.
        const secretEnv: Record<string, string> = {};

        const hostCapabilityDecision = await resolveHostCapabilityDecision(command, ctx);
        if (hostCapabilityDecision === "denied") {
          return { block: true, reason: "Sandbox: host toolchain approval denied." };
        }
        if (hostCapabilityDecision === "allowed" && !forceSrtForReadOnlyAccess) return undefined;

        // Use the policy-resolved profile (includes dynamic grants for network/path)
        const repoRoot = resolveRepoRoot(ctx.cwd);
        const result = await getSandboxBackend(ctx.cwd).wrapCommand({
          command,
          sandboxConfig: configWithSrtBoundary(effectiveConfig, forceSrtForReadOnlyAccess),
          cwd: ctx.cwd,
          repoRoot,
          unmaskedPaths,
          preResolvedProfile: resolved.profile,
          secretEnv,
          unifiedConfig: { network: getNetworkConfig(ctx.cwd) },
          approvedDomains: approvedNetworkDomains,
        });
        if (result && "block" in result) {
          return { block: true, reason: result.reason };
        }
        if (result && "command" in result) {
          (e.input as { command: string }).command = result.command;
          if (e.toolCallId && (
            result.cleanup
            || result.helperPayloadBytes !== undefined
            || result.rawCommandBytes !== undefined
            || autoAllowedDotenvPaths.length > 0
            || protectedReadPaths.length > 0
            || redactProtectedReadOutput
          )) {
            pendingSrtWraps.set(e.toolCallId, {
              cleanup: result.cleanup,
              helperPayloadBytes: result.helperPayloadBytes,
              rawCommandBytes: result.rawCommandBytes,
              dotenvPaths: autoAllowedDotenvPaths,
              redactOutput: redactProtectedReadOutput,
            });
          }
        }
      }
    }

    // 3. Delegate to upstream PermissionGateHandler (existing gates)
    if (bashPermissionAlreadyChecked) return undefined;
    try {
      return await gates.handleToolCall(event, ctx);
    } catch {
      return { block: true, reason: "Permission authorization failed; command blocked." };
    }
  })().catch(() => ({
    block: true,
    reason: "Permission authorization failed; command blocked.",
  })));

  // ── Augmented user_bash handler (our addition) ────────────────────────
  const blockedUserBash = (reason: string) => ({
    result: {
      output: `${reason}\n`,
      exitCode: 1,
      cancelled: false,
      truncated: false,
    },
  });

  const handleUserBash = async (
    event: { command: string; cwd: string },
    ctx: ExtensionContext,
  ) => {
    activeWorkspaceCwd = event.cwd;
    let sc: SandboxConfig;
    let policyManager: SandboxPolicyManager;
    try {
      sc = getSandboxConfig(event.cwd);
      policyManager = getPolicyManager();
    } catch {
      return {
        result: {
          output: "Permission config unavailable; command blocked.\n",
          exitCode: 1,
          cancelled: false,
          truncated: false,
        },
      };
    }
    let protectedReadPaths: string[];
    let sandboxedUserBash: boolean;
    let forceSrtForReadOnlyAccess = false;
    try {
      const sandboxAccess = await resolveBashSandboxAccess(
        event.command,
        event.cwd,
        resolveRepoRoot(event.cwd),
        sc,
        shouldBypassSandboxCommand(event.command, sc.bypassCommands),
      );
      if (sandboxAccess.blockReason) return blockedUserBash(sandboxAccess.blockReason);
      protectedReadPaths = sandboxAccess.protectedReadPaths;
      sandboxedUserBash = sandboxAccess.sandboxed;
      forceSrtForReadOnlyAccess = sandboxAccess.forceSrt;
    } catch {
      return blockedUserBash("Sandbox: unable to verify credential access; command blocked.");
    }
    // Network domain gate for user bash
    let hardBlockedMutationPaths: string[];
    try {
      const externalPaths = await extractExternalPathsFromBashCommand(
        event.command,
        event.cwd,
      );
      hardBlockedMutationPaths = getHardBlockedBashMutationPaths(
        event.command,
        event.cwd,
        externalPaths,
      );
    } catch {
      return blockedUserBash("Bash mutation path check unavailable; command blocked.");
    }
    if (hardBlockedMutationPaths.length > 0) {
      return blockedUserBash(
        "Blocked mutating Bash command outside workspace or temporary roots: "
        + hardBlockedMutationPaths.join(", "),
      );
    }

    const networkResult = await handleNetworkUserBash(
      event as Parameters<typeof handleNetworkUserBash>[0],
      ctx,
      {
        getNetworkConfig,
        getAgentDir: getAgentDir,
        promptWaitTracker,
        persistNetworkGrants: (domains, scope, state) =>
          persistNetworkGrantTransaction(policyManager, event.cwd, domains, scope, state),
      },
    );
    if (networkResult?.result) {
      return networkResult;
    }
    const approvedNetworkDomains = [
      ...getSessionNetworkApprovals(),
      ...(networkResult?.approvedDomains ?? []),
    ];

    // Sandbox wrapping for user bash (same gate path as tool_call)
    if (sc.enabled) {
      if (!sandboxedUserBash) return undefined;

      // Same masked-file gate for user_bash
      // (masked files show "(masked)" content; block if user hasn't granted access)
      let effectiveConfig = getEffectiveSandboxConfig(event.cwd);
      policyManager.updateConfig(effectiveConfig);
      let resolvedProfile = policyManager.resolveProfile(event.command, event.cwd, resolveRepoRoot(event.cwd));
      let networkApprovedForInvocation = false;
      const invocationPathGrants: { path: string; mode: "ro" | "rw" }[] = [];

      if (!resolvedProfile.canExecute && resolvedProfile.requiredChanges) {
        const change = resolvedProfile.requiredChanges;
        const promptResult = await promptSandboxGrant(ctx, {
          change,
          command: event.command,
          promptWaitTracker,
        });

        if (promptResult.action === "deny") {
          return {
            result: {
              output: `Sandbox: ${change.description}. User denied.\n`,
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }

        if (change.type === "network") {
          if (promptResult.duration === "once") {
            networkApprovedForInvocation = true;
          } else {
          let configPath: string | undefined;
          let snapshots: ConfigSnapshot[] = [];
          let grants: Grant[] = [];
          try {
            if (promptResult.duration === "always") {
              const scope = promptResult.scope ?? "global";
              configPath = getSafeScopedConfigPath(scope, event.cwd);
              snapshots = snapshotConfigs([configPath]);
              persistScopedSandboxNetworkGrant(scope, event.cwd);
            }
            grants = policyManager.grantNetwork(change.values, {
              duration: promptResult.duration,
              projectRoot: resolveRepoRoot(event.cwd),
            });
            if (configPath) {
              for (const grant of grants) {
                rememberPersistentGrant(grant, { kind: "sandbox-network", configPath, scope: promptResult.scope ?? "global" });
              }
              sandboxRuntime.reloadConfig();
              effectiveConfig = getEffectiveSandboxConfig(event.cwd);
              policyManager.updateConfig(effectiveConfig);
            }
          } catch {
            rollbackSandboxChanges(policyManager, grants, snapshots, promptResult.scope === "workspace" ? event.cwd : undefined);
            return {
              result: {
                output: "Sandbox: failed to persist network approval; command blocked.\n",
                exitCode: 1,
                cancelled: false,
                truncated: false,
              },
            };
          }
        }
        } else if (change.type === "path") {
          const grants: Grant[] = [];
          let snapshots: ConfigSnapshot[] = [];
          try {
            for (const path of change.values) {
              if (promptResult.duration === "once") {
                invocationPathGrants.push({ path, mode: change.mode ?? "ro" });
                continue;
              }
              let configPath: string | undefined;
              if (promptResult.duration === "always") {
                const scope = promptResult.scope ?? "global";
                configPath = getSafeScopedConfigPath(scope, event.cwd);
                if (snapshots.length === 0) snapshots = snapshotConfigs([configPath]);
                persistScopedSandboxPathGrant(scope, event.cwd, path, change.mode ?? "ro");
              }
              const grant = policyManager.grantPath(path, change.mode ?? "ro", {
                duration: promptResult.duration,
                projectRoot: resolveRepoRoot(event.cwd),
              });
              grants.push(grant);
              if (configPath) {
                rememberPersistentGrant(grant, { kind: "path", configPath, value: path, scope: promptResult.scope ?? "global" });
                sandboxRuntime.reloadConfig();
              }
            }
          } catch {
            rollbackSandboxChanges(policyManager, grants, snapshots, promptResult.scope === "workspace" ? event.cwd : undefined);
            return {
              result: {
                output: "Sandbox: failed to persist path approval; command blocked.\n",
                exitCode: 1,
                cancelled: false,
                truncated: false,
              },
            };
          }
        }

        resolvedProfile = policyManager.resolveProfile(
          event.command,
          event.cwd,
          resolveRepoRoot(event.cwd),
          { network: networkApprovedForInvocation, pathGrants: invocationPathGrants },
        );
      }

      let activeProfile = resolvedProfile.profile;

      // Collect active grants to avoid double-prompting
      const activeGrantPaths = new Set(
        policyManager.listGrants(resolveRepoRoot(event.cwd))
          .filter((g) => g.type === "path")
          .map((g) => g.value),
      );
      const maskedResolution = await resolveMaskedAuthAccess(
        event.command,
        event.cwd,
        resolveRepoRoot(event.cwd),
        activeProfile,
        effectiveConfig,
        ctx,
        promptWaitTracker,
        activeGrantPaths,
        {
          autoAllowWorkspaceDotenvRead: true,
          requireSrtBoundary: forceSrtForReadOnlyAccess && protectedReadPaths.length === 0,
        },
      );
      if (maskedResolution.blockReason) {
        return {
          result: {
            output: maskedResolution.blockReason,
            exitCode: 1,
            cancelled: false,
            truncated: false,
          },
        };
      }
      if (maskedResolution.bypass) {
        return undefined;
      }
      const unmaskedPaths: UnmaskedPath[] = maskedResolution.unmaskedPaths;

      // External path gate for user_bash
      const externalPaths = await detectExternalPaths(
        event.command,
        event.cwd,
        activeProfile,
        effectiveConfig,
        undefined,
        unmaskedPaths.map((entry) => entry.path),
      );
      let externalWritePaths: Awaited<ReturnType<typeof detectExternalWritePaths>>;
      try {
        externalWritePaths = await detectExternalWritePaths(
          event.command, event.cwd, activeProfile, effectiveConfig,
        );
      } catch (error) {
        const detail = error instanceof Error && error.message
          ? error.message
          : "invalid external write target";
        return blockedUserBash("Sandbox: " + detail + "; command blocked.");
      }
      const approvalGroups = [
        {
          mode: "ro" as const,
          paths: externalPaths.filter(
            (entry) =>
              !externalWritePaths.some(
                (write) =>
                  entry.path === write.path ||
                  (write.isDirectory && isPathWithinDirectory(entry.path, write.path)),
              ) && !activeGrantPaths.has(entry.path),
          ),
        },
        { mode: "rw" as const, paths: externalWritePaths },
      ];
      let promptedForExternalPaths = false;
      for (const { mode, paths } of approvalGroups) {
        if (paths.length === 0) continue;
        promptedForExternalPaths = true;
        const extPromptResult = await promptSandboxGrant(ctx, {
          change: {
            type: "path",
            mode,
            values: paths.map((entry) => entry.path),
            description: formatExternalPathPrompt(paths, event.command, mode),
          },
          command: event.command,
          promptWaitTracker,
        });

        if (extPromptResult.action === "deny") {
          return {
            result: {
              output:
                "Sandbox: external paths not granted: "
                + paths.map((entry) => entry.displayPath).join(", "),
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }

        if (extPromptResult.duration === "once") {
          for (const { path } of paths) {
            invocationPathGrants.push({ path, mode });
            activeGrantPaths.add(path);
          }
          continue;
        }

        const grants: Grant[] = [];
        let snapshots: ConfigSnapshot[] = [];
        try {
          const scope = extPromptResult.scope ?? "global";
          for (const entry of paths) {
            const configPath = extPromptResult.duration === "always"
              ? getSafeScopedConfigPath(scope, event.cwd)
              : undefined;
            if (configPath && snapshots.length === 0) snapshots = snapshotConfigs([configPath]);
            if (extPromptResult.duration === "always") {
              persistScopedSandboxPathGrant(scope, event.cwd, entry.path, mode);
            }
            const grant = policyManager.grantPath(entry.path, mode, {
              duration: extPromptResult.duration,
              projectRoot: resolveRepoRoot(event.cwd),
            });
            grants.push(grant);
            activeGrantPaths.add(entry.path);
            if (configPath) rememberPersistentGrant(grant, { kind: "path", configPath, value: entry.path, scope });
          }

          if (extPromptResult.duration === "always") {
            effectiveConfig = getEffectiveSandboxConfig(event.cwd);
            policyManager.updateConfig(effectiveConfig);
          }
        } catch {
          rollbackSandboxChanges(policyManager, grants, snapshots, extPromptResult.scope === "workspace" ? event.cwd : undefined);
          return {
            result: {
              output: "Sandbox: failed to persist external path approval; command blocked.\n",
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }
      }

      if (promptedForExternalPaths) {
        activeProfile = policyManager.resolveProfile(
          event.command,
          event.cwd,
          resolveRepoRoot(event.cwd),
          { network: networkApprovedForInvocation, pathGrants: invocationPathGrants },
        ).profile;
      }
      const hostCapabilityDecision = await resolveHostCapabilityDecision(event.command, ctx);
      if (hostCapabilityDecision === "denied") {
        return blockedUserBash("Sandbox: host toolchain approval denied.");
      }
      if (hostCapabilityDecision === "allowed" && !forceSrtForReadOnlyAccess) return undefined;

      // Env vars and config dirs are always available by default in sandbox.
      const secretEnv: Record<string, string> = {};

      return {
        operations: getSandboxBackend(event.cwd).createBashOperations({
          sandboxConfig: configWithSrtBoundary(effectiveConfig, forceSrtForReadOnlyAccess),
          cwd: event.cwd,
          repoRoot: resolveRepoRoot(event.cwd),
          unmaskedPaths,
          preResolvedProfile: activeProfile,
          secretEnv,
          unifiedConfig: { network: getNetworkConfig(event.cwd) },
          approvedDomains: approvedNetworkDomains,
        }),
      };
    }

    return undefined;
  };

  pi.on("user_bash", (event: { command: string; cwd: string }, ctx: ExtensionContext) => {
    clipboardTempCleanup.trackText(event.command);
    return handleUserBash(event, ctx).catch(() => blockedUserBash("Permission authorization failed; command blocked."));
  });

  pi.on("tool_result", async (event, ctx) => {
    const wrapped = pendingSrtWraps.get(event.toolCallId);
    if (wrapped) {
      pendingSrtWraps.delete(event.toolCallId);
      wrapped.cleanup?.();
    }

    if (event.toolName === "read") {
      const failClosed = () => {
        const content = [{ type: "text" as const, text: "****" }];
        try {
          const details = maskDotenvReadDetails(event.details, () => "****");
          return details === undefined ? { content } : { content, details };
        } catch {
          return { content };
        }
      };

      try {
        const readPath = getPathBearingToolPath(event.toolName, event.input);
        if (readPath && isProtectedCredentialReadPath(readPath, ctx.cwd)) {
          return fullyRedactedResult(event.details);
        }
        if (readPath && isSensitiveEnvPath(readPath, ctx.cwd)) {
          if (event.isError) return failClosed();

          const sourcePath = resolveReadPathForComparison(readPath, ctx.cwd);
          const sourceText = await readDotenvSourceWithinLimit(sourcePath);
          if (sourceText === null) return failClosed();

          const mapSensitiveContent = (maskText: (text: string) => string) => event.content.map((item) =>
            item.type === "text"
              ? { ...item, text: maskText(item.text) }
              : { type: "text" as const, text: "****" },
          );
          const sourceLines = sourceText.split("\n");
          const rawOffset = event.input.offset;
          const startLine = typeof rawOffset === "number" && rawOffset
            ? Math.max(0, rawOffset - 1)
            : 0;
          const startLineIndex = Math.trunc(startLine);
          const rawLimit = event.input.limit;
          const selectedLineCount = sourceLines.slice(
            startLine,
            typeof rawLimit === "number" ? Math.min(startLine + rawLimit, sourceLines.length) : undefined,
          ).length;
          const truncation = toRecord(toRecord(event.details).truncation);
          const outputLineCount = truncation.truncated === true && typeof truncation.outputLines === "number"
            ? truncation.outputLines
            : selectedLineCount;

          const maskResultText = (text: string) =>
            maskDotenvReadResult(text, sourceText, startLineIndex, outputLineCount);
          return {
            content: mapSensitiveContent(maskResultText),
            details: maskDotenvReadDetails(event.details, maskResultText),
          };
        }
      } catch {
        return failClosed();
      }
    }

    if (wrapped?.redactOutput) return fullyRedactedResult(event.details);

    let dotenvOutputResult: { content: typeof event.content; details?: unknown } | undefined;
    if (wrapped?.dotenvPaths?.length) {
      const failClosed = () => ({
        content: [{ type: "text" as const, text: "****" }],
        details: maskDotenvReadDetails(event.details, () => "****"),
      });
      try {
        if (event.toolName !== "bash") {
          dotenvOutputResult = failClosed();
        } else {
          const maskingValues = (await Promise.all(wrapped.dotenvPaths.map(parseDotenvValues))).flat();
          const maskOutputText = (text: string) => {
            const commentsMasked = text.replace(/^(\uFEFF?[ \t\r]*#)[^\r\n]*/gm, "$1 ****");
            return maskSecretValues(commentsMasked, maskingValues);
          };
          dotenvOutputResult = {
            content: event.content.map((item) => item.type === "text"
              ? { ...item, text: maskOutputText(item.text) }
              : { type: "text" as const, text: "****" }),
            details: maskDotenvReadDetails(event.details, maskOutputText),
          };
        }
      } catch {
        dotenvOutputResult = failClosed();
      }
    }

    const text = event.content.length === 1 && event.content[0]?.type === "text"
      ? event.content[0].text.trim()
      : "";
    const isPiSpawnE2Big = /^spawn(?:[ \t]+.+)?[ \t]+E2BIG$/.test(text);
    const isHelperSpawnE2Big = /^sandbox-run error: spawn(?:[ \t]+.+)?[ \t]+E2BIG$/.test(text);
    if (event.toolName !== "bash" || !event.isError || (!isPiSpawnE2Big && !isHelperSpawnE2Big)) {
      return dotenvOutputResult;
    }

    const command = event.input.command;
    runtime.writeDebugLog("spawn.e2big", {
      route: isHelperSpawnE2Big ? "srt-helper" : "pi-bash",
      errorCode: "E2BIG",
      commandBytes: typeof command === "string" ? Buffer.byteLength(command, "utf8") : null,
      rawCommandBytes: wrapped?.rawCommandBytes ?? null,
      helperPayloadBytes: wrapped?.helperPayloadBytes ?? null,
      srtWrappedCommand: typeof command === "string" && (
        command.includes(DEFAULT_SRT_HELPER_ENV + "=") ||
        command.includes(DEFAULT_SRT_HELPER_INPUT_FILE_ENV + "=")
      ),
      processEnvironment: summarizeEnvironmentSizes(process.env),
    });
    return dotenvOutputResult;
  });
}
