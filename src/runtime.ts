import { existsSync } from "node:fs";
import { join, normalize } from "node:path";
import {
  type ExtensionCommandContext,
  type ExtensionContext,
  getAgentDir,
} from "@earendil-works/pi-coding-agent";

import {
  loadAndMergeConfigs,
  normalizeUnifiedConfig,
  stripLegacyYoloAutoMaxLevel,
  type ConfigModeLayer,
  type MergedConfigResult,
  type ModeLayerId,
} from "./config-loader";
import {
  DEBUG_LOG_FILENAME,
  getBundledConfigPath,
  getGlobalConfigPath,
  getLegacyGlobalPolicyPath,
  getLegacyProjectConfigPath,
  getLegacyProjectExtensionConfigPath,
  getLegacyProjectPolicyPath,
  getProjectConfigPath,
  REVIEW_LOG_FILENAME,
} from "./config-paths";
import { buildResolvedConfigLogEntry } from "./config-reporter";
import {
  DEFAULT_EXTENSION_CONFIG,
  EXTENSION_ROOT,
  ensurePermissionSystemLogsDirectory,
  normalizePermissionSystemConfig,
  type ModeScope,
  type PermissionMode,
  type PermissionSystemExtensionConfig,
} from "./extension-config";
import { computeExtensionPaths, type ExtensionPaths } from "./extension-paths";

export type { ExtensionPaths } from "./extension-paths";

import { createPermissionSystemLogger } from "./logging";
import { PermissionManager } from "./permission-manager";
import { SessionRules } from "./session-rules";
import type { SkillPromptEntry } from "./skill-prompt-sanitizer";
import {
  getScopedConfigPath,
  persistPermissionRuleToConfig,
  readConfigFile,
  writeConfigFile,
  type PersistentApprovalScope,
} from "./scoped-config";
import { syncPermissionSystemStatus } from "./status";

/**
 * Mutable session state — the subset of ExtensionRuntime that holds
 * per-session fields. `PermissionSession` now owns these for handler
 * use; this interface remains so `ExtensionRuntime` can still serve
 * as the internal composition root (config-modal, RPC handlers).
 */
interface SessionState {
  runtimeContext: ExtensionContext | null;
  permissionManager: PermissionManager;
  readonly sessionRules: SessionRules;
  activeSkillEntries: SkillPromptEntry[];
  lastKnownActiveAgentName: string | null;
  lastActiveToolsCacheKey: string | null;
  lastPromptStateCacheKey: string | null;
}

interface RuntimeModeResolution {
  cwd: string;
  layers: ConfigModeLayer[];
  configuredMode: PermissionMode;
  source: ModeLayerId;
}

/**
 * Runtime context object created once inside `piPermissionSystemExtension()`.
 *
 * Holds all path constants (derived from `getAgentDir()` at construction time),
 * mutable extension state, and the log-writing methods — eliminating the
 * module-scope cached constants and setter-injection pattern that previously
 * lived in `src/index.ts`.
 *
 * Tests construct this via `createExtensionRuntime({ agentDir: tmpDir })`
 * without timing issues around `PI_CODING_AGENT_DIR`.
 */
export interface ExtensionRuntime extends ExtensionPaths, SessionState {
  // ── Mutable state (beyond SessionState) ───────────────────────────────────
  config: PermissionSystemExtensionConfig;
  /** In-memory mode choice for this session; overrides file config and PI_SENTINEL_MODE. */
  sessionMode?: PermissionMode;
  /** Mode provenance from the same config load that produced `config`. */
  modeResolution: RuntimeModeResolution | null;
  lastConfigWarning: string | null;
  /** Most recent interactive (UI) session id observed in this process. */
  lastKnownInteractiveSessionId: string | null;
  /** Interactive session ids keyed by normalized cwd for better parent routing. */
  interactiveSessionIdsByCwd: Map<string, string>;

  // ── Logging (backed by logger created at construction) ─────────────────
  writeDebugLog(event: string, details?: Record<string, unknown>): void;
  writeReviewLog(event: string, details?: Record<string, unknown>): void;
}

// ── Pure helpers ───────────────────────────────────────────────────────────

/**
 * Derive Pi project-level config and agents paths from a working directory.
 * Returns null when cwd is absent (headless / global-only config).
 */
export function derivePiProjectPaths(cwd: string | undefined | null): {
  projectGlobalConfigPath: string;
  legacyProjectGlobalConfigPath: string;
  legacyProjectConfigPath: string;
  legacyProjectPolicyPath: string;
  projectAgentsDir: string;
} | null {
  if (!cwd) {
    return null;
  }
  return {
    projectGlobalConfigPath: getProjectConfigPath(cwd),
    legacyProjectGlobalConfigPath: getLegacyProjectConfigPath(cwd),
    legacyProjectConfigPath: getLegacyProjectExtensionConfigPath(cwd),
    legacyProjectPolicyPath: getLegacyProjectPolicyPath(cwd),
    projectAgentsDir: join(cwd, ".pi", "agent", "agents"),
  };
}

/**
 * Create a new PermissionManager scoped to a working directory's config hierarchy.
 * Pass `cwd` as null/undefined to use global config only.
 */
export function createPermissionManagerForCwd(
  agentDir: string,
  cwd: string | undefined | null,
): PermissionManager {
  const projectPaths = derivePiProjectPaths(cwd);
  return new PermissionManager({
    bundledConfigPath: getBundledConfigPath(EXTENSION_ROOT),
    globalConfigPath: getGlobalConfigPath(agentDir),
    projectGlobalConfigPath: projectPaths?.projectGlobalConfigPath,
    legacyProjectGlobalConfigPath: projectPaths?.legacyProjectGlobalConfigPath,
    legacyProjectConfigPath: projectPaths?.legacyProjectConfigPath,
    legacyProjectPolicyPath: projectPaths?.legacyProjectPolicyPath,
    projectAgentsDir: projectPaths?.projectAgentsDir,
  });
}

function withSessionMode(
  runtime: Pick<ExtensionRuntime, "sessionMode">,
  config: PermissionSystemExtensionConfig,
): PermissionSystemExtensionConfig {
  return runtime.sessionMode ? { ...config, mode: runtime.sessionMode } : config;
}

function createModeResolution(
  cwd: string | null | undefined,
  mergeResult: MergedConfigResult,
): RuntimeModeResolution {
  return {
    cwd: cwd ?? "",
    layers: mergeResult.modeLayers,
    configuredMode: normalizePermissionSystemConfig(mergeResult.merged).mode,
    source: mergeResult.modeSource,
  };
}

/**
 * Reload merged config from disk into the runtime.
 * If `ctx` is provided, updates `runtime.runtimeContext` first.
 */
export function refreshExtensionConfig(
  runtime: ExtensionRuntime,
  ctx?: ExtensionContext,
): void {
  if (ctx) {
    runtime.runtimeContext = ctx;
  }
  const cwd = runtime.runtimeContext?.cwd ?? null;
  const mergeResult = loadAndMergeConfigs(
    runtime.agentDir,
    cwd ?? "",
    EXTENSION_ROOT,
  );
  const configuredConfig = normalizePermissionSystemConfig(mergeResult.merged);
  runtime.modeResolution = createModeResolution(cwd, mergeResult);
  const runtimeConfig = withSessionMode(runtime, configuredConfig);
  runtime.config = runtimeConfig;

  if (runtime.runtimeContext?.hasUI) {
    syncPermissionSystemStatus(runtime.runtimeContext, runtimeConfig);
  }

  const warning =
    mergeResult.issues.length > 0 ? mergeResult.issues.join("\n") : undefined;

  if (warning && warning !== runtime.lastConfigWarning) {
    runtime.lastConfigWarning = warning;
    runtime.runtimeContext?.ui.notify(warning, "warning");
  } else if (!warning) {
    runtime.lastConfigWarning = null;
  }

  runtime.writeDebugLog("config.loaded", {
    warning: warning ?? null,
    debugLog: runtimeConfig.debugLog,
    permissionReviewLog: runtimeConfig.permissionReviewLog,
    mode: runtimeConfig.mode,
    yoloAskBashPatterns: runtimeConfig.yoloAskBashPatterns,
  });
}

/**
 * Apply a `pi-sentinel:set-session-mode` event from another extension
 * (e.g. `/implement --yolo` without `--worktree`). Mirrors the `/sentinel`
 * modal's session-scope mode choice: in-memory only, never written to disk.
 */
export function applySessionModeEvent(
  runtime: ExtensionRuntime,
  event: unknown,
): void {
  const requestedMode = (event as { mode?: unknown } | null)?.mode;
  const normalized = normalizeUnifiedConfig({ mode: requestedMode }).config.mode;
  if (normalized === undefined) {
    runtime.writeDebugLog("session_mode_event.invalid", { requestedMode });
    return;
  }
  runtime.sessionMode = normalized;
  refreshExtensionConfig(runtime);
  runtime.writeDebugLog("session_mode_event.applied", { mode: normalized });
}

/**
 * Save updated runtime knobs (debugLog, permissionReviewLog, mode,
 * yoloAskBashPatterns) to the global config file, then update runtime.config
 * and sync UI status.
 */
/** Persist global `sandbox.enabled`, keeping other sandbox keys. Returns false on failure. */
export function saveSandboxEnabled(
  runtime: ExtensionRuntime,
  enabled: boolean,
  ctx: ExtensionCommandContext,
): boolean {
  const globalPath = getGlobalConfigPath(runtime.agentDir);
  try {
    const existing = readConfigFile(globalPath);
    const sandbox = typeof existing.sandbox === "object" && existing.sandbox !== null && !Array.isArray(existing.sandbox)
      ? existing.sandbox
      : {};
    if (writeConfigFile(globalPath, { ...existing, sandbox: { ...sandbox, enabled } })) {
      runtime.writeDebugLog("config.sandbox_toggled", { enabled });
      return true;
    }
  } catch (error) {
    ctx.ui.notify(`Failed to save sandbox setting at '${globalPath}': ${error instanceof Error ? error.message : String(error)}`, "error");
    return false;
  }
  ctx.ui.notify(`Failed to save sandbox setting at '${globalPath}'.`, "error");
  return false;
}

/** Write `mode` to the project permissions file; true when saved. */
function saveProjectMode(
  runtime: ExtensionRuntime,
  mode: PermissionMode,
  ctx: ExtensionCommandContext,
): boolean {
  const cwd = runtime.runtimeContext?.cwd ?? ctx.cwd;
  if (!cwd) {
    ctx.ui.notify("Cannot save project mode: no project directory.", "error");
    return false;
  }
  const projectPath = getScopedConfigPath(runtime.agentDir, cwd, "workspace");
  try {
    const next: Record<string, unknown> = { ...readConfigFile(projectPath), mode };
    delete next.yoloMode;
    delete next.yoloAutoMode;
    if (writeConfigFile(projectPath, next, cwd)) {
      return true;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    ctx.ui.notify(`Failed to save project mode at '${projectPath}': ${message}`, "error");
    return false;
  }
  ctx.ui.notify(`Failed to save project mode at '${projectPath}'.`, "error");
  return false;
}

export interface ModeLayer extends ConfigModeLayer {
  /** Actual project save target; it may reuse the legacy project config file. */
  savePath?: string;
}

export interface ModeLayers {
  layers: ModeLayer[];
  effective: PermissionMode;
  source: ModeLayerId;
}

export function getModeLayers(
  runtime: Pick<ExtensionRuntime, "agentDir" | "sessionMode"> &
    Partial<Pick<ExtensionRuntime, "config" | "modeResolution">>,
  cwd?: string | null,
): ModeLayers {
  const resolution = runtime.modeResolution;
  const mergedConfig = resolution
    ? undefined
    : loadAndMergeConfigs(runtime.agentDir, cwd ?? "", EXTENSION_ROOT);
  const configuredMode = resolution?.configuredMode
    ?? normalizePermissionSystemConfig(mergedConfig!.merged).mode;
  const effective = runtime.config?.mode ?? runtime.sessionMode ?? configuredMode;
  const projectCwd = cwd ?? resolution?.cwd ?? "";
  const projectSavePath = projectCwd
    ? getScopedConfigPath(runtime.agentDir, projectCwd, "workspace")
    : undefined;
  const modeLayers = (resolution?.layers ?? mergedConfig!.modeLayers).map((layer) =>
    layer.id === "project" && projectSavePath ? { ...layer, savePath: projectSavePath } : { ...layer }
  );

  return {
    layers: [
      { id: "session", name: "session", mode: runtime.sessionMode, path: "memory" },
      ...modeLayers,
    ],
    effective,
    source: runtime.sessionMode ? "session" : resolution?.source ?? mergedConfig!.modeSource,
  };
}

/** Persist logging settings, and the mode when `persistMode`, to the global file. */
function saveGlobalSettings(
  runtime: ExtensionRuntime,
  normalized: PermissionSystemExtensionConfig,
  persistMode: boolean,
  ctx: ExtensionCommandContext,
): boolean {
  const globalPath = getGlobalConfigPath(runtime.agentDir);

  let existing: ReturnType<typeof readConfigFile>;
  try {
    existing = readConfigFile(globalPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    ctx.ui.notify(
      `Failed to save pi-sentinel config at '${globalPath}': ${message}`,
      "error",
    );
    return false;
  }

  const merged: Record<string, unknown> = {
    ...existing,
    debugLog: normalized.debugLog,
    permissionReviewLog: normalized.permissionReviewLog,
    ...(persistMode ? { mode: normalized.mode } : {}),
    yoloAskBashPatterns: normalized.yoloAskBashPatterns,
  };

  stripLegacyYoloAutoMaxLevel(merged);
  if (persistMode) {
    delete merged.yoloMode;
    delete merged.yoloAutoMode;
  }

  if (!writeConfigFile(globalPath, merged)) {
    ctx.ui.notify(
      `Failed to save pi-sentinel config at '${globalPath}'.`,
      "error",
    );
    return false;
  }
  return true;
}

function applySavedConfig(
  runtime: ExtensionRuntime,
  ctx: ExtensionCommandContext,
  normalized: PermissionSystemExtensionConfig,
  mode: PermissionMode,
): void {
  const effectiveConfig = withSessionMode(runtime, { ...normalized, mode });
  runtime.config = effectiveConfig;
  syncPermissionSystemStatus(ctx, effectiveConfig);
  runtime.lastConfigWarning = null;
  runtime.writeDebugLog("config.saved", {
    debugLog: effectiveConfig.debugLog,
    permissionReviewLog: effectiveConfig.permissionReviewLog,
    mode: effectiveConfig.mode,
    yoloAskBashPatterns: effectiveConfig.yoloAskBashPatterns,
  });
}

/**
 * Save settings from the /sentinel modal. An explicit Mode choice goes to
 * `modeScope`: session (memory only), project, or global. Persistent scopes
 * replace any session mode. Other settings always save to the global file.
 */
export function saveExtensionConfig(
  runtime: ExtensionRuntime,
  next: PermissionSystemExtensionConfig,
  ctx: ExtensionCommandContext,
  modeWasExplicitlySelected = false,
  modeScope: ModeScope = "global",
): boolean {
  const normalized = normalizePermissionSystemConfig(next);

  if (modeWasExplicitlySelected && modeScope === "session") {
    runtime.sessionMode = normalized.mode;
    applySavedConfig(runtime, ctx, normalized, normalized.mode);
    return true;
  }

  const modeOverride = normalizeUnifiedConfig({
    mode: process.env.PI_SENTINEL_MODE,
  }).config.mode;
  const saved = modeWasExplicitlySelected && modeScope === "project"
    ? saveProjectMode(runtime, normalized.mode, ctx)
    : saveGlobalSettings(
      runtime,
      normalized,
      modeWasExplicitlySelected
        || (modeOverride === undefined && runtime.sessionMode === undefined),
      ctx,
    );
  if (!saved) return false;

  if (modeWasExplicitlySelected) {
    runtime.sessionMode = undefined;
  }
  const cwd = runtime.runtimeContext?.cwd ?? ctx.cwd ?? "";
  const mergeResult = loadAndMergeConfigs(runtime.agentDir, cwd, EXTENSION_ROOT);
  runtime.modeResolution = createModeResolution(cwd, mergeResult);
  applySavedConfig(
    runtime,
    ctx,
    normalized,
    normalizePermissionSystemConfig(mergeResult.merged).mode,
  );
  return true;
}

/**
 * Remove runtime overrides so bundled defaults become effective.
 */
export function resetExtensionConfig(
  runtime: ExtensionRuntime,
  ctx: ExtensionCommandContext,
): void {
  const globalPath = getGlobalConfigPath(runtime.agentDir);
  let existing: ReturnType<typeof readConfigFile>;
  try {
    existing = readConfigFile(globalPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    ctx.ui.notify(
      `Failed to reset pi-sentinel config at '${globalPath}': ${message}`,
      "error",
    );
    return;
  }

  const next = { ...existing };
  delete next.debugLog;
  delete next.permissionReviewLog;
  delete next.mode;
  delete next.yoloMode;
  delete next.yoloAutoMode;
  stripLegacyYoloAutoMaxLevel(next);
  delete next.yoloAskBashPatterns;

  if (!writeConfigFile(globalPath, next)) {
    ctx.ui.notify(
      `Failed to reset pi-sentinel config at '${globalPath}'.`,
      "error",
    );
    return;
  }

  const cwd = runtime.runtimeContext?.cwd ?? ctx.cwd ?? "";
  const mergeResult = loadAndMergeConfigs(runtime.agentDir, cwd, EXTENSION_ROOT);
  runtime.modeResolution = createModeResolution(cwd, mergeResult);
  runtime.config = withSessionMode(
    runtime,
    normalizePermissionSystemConfig(mergeResult.merged),
  );
  runtime.lastConfigWarning =
    mergeResult.issues.length > 0 ? mergeResult.issues.join("\n") : null;
  syncPermissionSystemStatus(ctx, runtime.config);
  runtime.writeDebugLog("config.reset");
}

export function persistPermissionRule(
  runtime: ExtensionRuntime,
  cwd: string | undefined,
  scope: PersistentApprovalScope,
  surface: string,
  pattern: string,
): void {
  const configPath = getScopedConfigPath(runtime.agentDir, cwd ?? null, scope);
  persistPermissionRuleToConfig(
    configPath,
    surface,
    pattern,
    "allow",
    scope === "workspace" ? cwd : undefined,
  );
  runtime.writeDebugLog("permission.persisted", {
    scope,
    surface,
    pattern,
    configPath,
  });
}

/**
 * Write the resolved config path set (bundled, global, project, and legacy) to
 * the review and debug logs.
 */
export function logResolvedConfigPaths(runtime: ExtensionRuntime): void {
  const policyPaths = runtime.permissionManager.getResolvedPolicyPaths();
  const cwd = runtime.runtimeContext?.cwd ?? null;
  const { agentDir } = runtime;
  const legacyGlobalPolicyDetected = existsSync(
    getLegacyGlobalPolicyPath(agentDir),
  );
  const legacyProjectPolicyDetected = cwd
    ? existsSync(getLegacyProjectPolicyPath(cwd))
    : false;
  const entry = buildResolvedConfigLogEntry({
    policyPaths,
    legacyGlobalPolicyDetected,
    legacyProjectPolicyDetected,
    legacyExtensionConfigDetected: false,
  });
  runtime.writeReviewLog(
    "config.resolved",
    entry as unknown as Record<string, unknown>,
  );
  runtime.writeDebugLog(
    "config.resolved",
    entry as unknown as Record<string, unknown>,
  );
}

function normalizeCwdKey(cwd: string): string {
  return normalize(cwd);
}

type SharedInteractiveSessionRegistry = {
  latestSessionId: string | null;
  byCwd: Map<string, string>;
};

const SHARED_INTERACTIVE_SESSION_KEY = Symbol.for(
  "pi-sentinel:interactive-sessions",
);

function getSharedInteractiveSessionRegistry(): SharedInteractiveSessionRegistry {
  const existing = (globalThis as Record<symbol, unknown>)[
    SHARED_INTERACTIVE_SESSION_KEY
  ];
  if (
    existing &&
    typeof existing === "object" &&
    "byCwd" in existing &&
    (existing as { byCwd?: unknown }).byCwd instanceof Map
  ) {
    return existing as SharedInteractiveSessionRegistry;
  }

  const created: SharedInteractiveSessionRegistry = {
    latestSessionId: null,
    byCwd: new Map(),
  };
  (globalThis as Record<symbol, unknown>)[SHARED_INTERACTIVE_SESSION_KEY] =
    created;
  return created;
}

/** Record the latest interactive parent session for forwarding fallbacks. */
export function recordInteractiveSession(
  runtime: ExtensionRuntime,
  ctx: ExtensionContext,
): void {
  if (!ctx.hasUI) {
    return;
  }

  let sessionId: string | null = null;
  try {
    const raw = ctx.sessionManager.getSessionId();
    if (typeof raw === "string" && raw.trim()) {
      sessionId = raw.trim();
    }
  } catch {
    return;
  }

  if (!sessionId) {
    return;
  }

  runtime.lastKnownInteractiveSessionId = sessionId;
  const shared = getSharedInteractiveSessionRegistry();
  shared.latestSessionId = sessionId;
  if (ctx.cwd?.trim()) {
    const cwdKey = normalizeCwdKey(ctx.cwd);
    runtime.interactiveSessionIdsByCwd.set(cwdKey, sessionId);
    shared.byCwd.set(cwdKey, sessionId);
  }
}

/** Resolve fallback parent session id, preferring cwd match over global latest. */
export function resolveInteractiveSessionFallback(
  runtime: ExtensionRuntime,
  cwd: string | undefined | null,
): string | null {
  const shared = getSharedInteractiveSessionRegistry();
  if (cwd?.trim()) {
    const cwdKey = normalizeCwdKey(cwd);
    const byCwd = runtime.interactiveSessionIdsByCwd.get(cwdKey);
    if (byCwd) {
      return byCwd;
    }
    const sharedByCwd = shared.byCwd.get(cwdKey);
    if (sharedByCwd) {
      return sharedByCwd;
    }
  }

  const runtimeContext = runtime.runtimeContext;
  if (runtimeContext?.hasUI) {
    try {
      const sessionId = runtimeContext.sessionManager.getSessionId();
      if (typeof sessionId === "string" && sessionId.trim()) {
        return sessionId.trim();
      }
    } catch {
      // Fall through to cached latest id.
    }
  }

  return shared.latestSessionId ?? runtime.lastKnownInteractiveSessionId;
}

// ── Factory ────────────────────────────────────────────────────────────────

/**
 * Create a fully-initialized `ExtensionRuntime`.
 *
 * Calls `getAgentDir()` at invocation time (never at module scope), so tests
 * may set `PI_CODING_AGENT_DIR` before calling the factory.
 */
export function createExtensionRuntime(options?: {
  agentDir?: string;
}): ExtensionRuntime {
  const agentDir = options?.agentDir ?? getAgentDir();
  const paths = computeExtensionPaths(agentDir);

  // Build a plain-object runtime first so the logger's `getConfig` closure
  // can reference `runtime.config` directly (always reads current value).
  const runtime: ExtensionRuntime = {
    ...paths,
    config: { ...DEFAULT_EXTENSION_CONFIG },
    modeResolution: null,
    runtimeContext: null,
    permissionManager: createPermissionManagerForCwd(agentDir, undefined),
    activeSkillEntries: [],
    lastKnownActiveAgentName: null,
    lastActiveToolsCacheKey: null,
    lastPromptStateCacheKey: null,
    lastConfigWarning: null,
    lastKnownInteractiveSessionId: null,
    interactiveSessionIdsByCwd: new Map(),
    sessionRules: new SessionRules(),
    // Logging methods are replaced below after the logger is constructed.
    writeDebugLog: () => {},
    writeReviewLog: () => {},
  };

  const reportedLoggingWarnings = new Set<string>();
  const logger = createPermissionSystemLogger({
    // Reads runtime.config at call time — always current.
    getConfig: () => runtime.config,
    debugLogPath: join(paths.globalLogsDir, DEBUG_LOG_FILENAME),
    reviewLogPath: join(paths.globalLogsDir, REVIEW_LOG_FILENAME),
    ensureLogsDirectory: () =>
      ensurePermissionSystemLogsDirectory(paths.globalLogsDir),
  });

  const reportLoggingWarning = (message: string): void => {
    if (reportedLoggingWarnings.has(message)) {
      return;
    }
    reportedLoggingWarnings.add(message);
    // Reads runtime.runtimeContext at call time — always current.
    runtime.runtimeContext?.ui.notify(message, "warning");
  };

  runtime.writeDebugLog = (
    event: string,
    details: Record<string, unknown> = {},
  ): void => {
    const warning = logger.debug(event, details);
    if (warning) {
      reportLoggingWarning(warning);
    }
  };

  runtime.writeReviewLog = (
    event: string,
    details: Record<string, unknown> = {},
  ): void => {
    const warning = logger.review(event, details);
    if (warning) {
      reportLoggingWarning(warning);
    }
  };

  return runtime;
}
