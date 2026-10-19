import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { PromptWaitTracker } from "#src/prompt-state";

import {
  getActiveAgentName,
  getActiveAgentNameFromSystemPrompt,
} from "#src/active-agent";
import { toRecord } from "#src/common";
import type {
  PermissionPromptDecision,
  RequestPermissionOptions,
} from "#src/permission-dialog";
import {
  type ForwardedPermissionRequest,
  type ForwardedPermissionResponse,
  isForwardedPermissionRequestForSession,
  PERMISSION_FORWARDING_POLL_INTERVAL_MS,
  PERMISSION_FORWARDING_TIMEOUT_MS,
  resolvePermissionForwardingTargetSessionId,
  SUBAGENT_PARENT_SESSION_ENV_CANDIDATES,
} from "#src/permission-forwarding";
import { isSubagentExecutionContext } from "#src/subagent-context";

import {
  cleanupPermissionForwardingLocationIfEmpty,
  ensurePermissionForwardingLocation,
  type ForwardedPermissionLogger,
  getExistingPermissionForwardingLocation,
  listRequestFiles,
  logPermissionForwardingError,
  logPermissionForwardingWarning,
  readForwardedPermissionRequest,
  readForwardedPermissionResponse,
  safeDeleteFile,
  sleep,
  writeJsonFileAtomic,
} from "./io";

/**
 * Extract the PID from a forwarded permission request ID.
 * Request IDs follow the format: `${Date.now()}-${randomString}-${process.pid}`
 */
function extractPidFromRequestId(requestId: string): number | null {
  const lastDash = requestId.lastIndexOf("-");
  if (lastDash === -1) return null;
  const pid = parseInt(requestId.slice(lastDash + 1), 10);
  return Number.isFinite(pid) && pid > 0 ? pid : null;
}

/**
 * Check whether a process is still alive (signal 0 probes without killing).
 */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export interface PermissionForwardingDeps {
  forwardingDir: string;
  subagentSessionsDir: string;
  logger: ForwardedPermissionLogger;
  promptWaitTracker?: PromptWaitTracker;
  writeReviewLog: (event: string, details: Record<string, unknown>) => void;
  requestPermissionDecisionFromUi: (
    ui: ExtensionContext["ui"],
    title: string,
    message: string,
    options?: RequestPermissionOptions,
  ) => Promise<PermissionPromptDecision>;
  shouldAutoApprove: (request: ForwardedPermissionRequest) => boolean;
  /** Optional fallback resolver for in-process subagents lacking parent env markers. */
  resolveFallbackTargetSessionId?: (
    ctx: ExtensionContext,
  ) => string | null;
}

export function getSessionId(ctx: ExtensionContext): string {
  try {
    const sessionId = ctx.sessionManager.getSessionId();
    if (typeof sessionId === "string" && sessionId.trim()) {
      return sessionId.trim();
    }
  } catch {}

  return "unknown";
}

function getContextSystemPrompt(ctx: ExtensionContext): string | undefined {
  const getSystemPrompt = toRecord(ctx).getSystemPrompt;
  if (typeof getSystemPrompt !== "function") {
    return undefined;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- getSystemPrompt is a Pi SDK accessor returning any
    const systemPrompt = getSystemPrompt.call(ctx);
    return typeof systemPrompt === "string" ? systemPrompt : undefined;
  } catch (error) {
    // No deps available in this helper — warning silently dropped.
    logPermissionForwardingWarning(
      null,
      "Failed to read context system prompt for forwarded permission metadata",
      error,
    );
    return undefined;
  }
}

export function formatForwardedPermissionPrompt(
  request: ForwardedPermissionRequest,
): string {
  const agentName = request.requesterAgentName || "unknown";
  const sessionId = request.requesterSessionId || "unknown";
  return [
    `Subagent '${agentName}' requested permission.`,
    `Session ID: ${sessionId}`,
    "",
    request.message,
  ].join("\n");
}

export async function waitForForwardedPermissionApproval(
  ctx: ExtensionContext,
  message: string,
  deps: PermissionForwardingDeps,
  requestMetadata?: Pick<
    ForwardedPermissionRequest,
    "toolName" | "command" | "forcePromptInYolo" | "allowSession"
  >,
): Promise<PermissionPromptDecision> {
  const requesterSessionId = getSessionId(ctx);
  const fallbackTargetSessionId = deps.resolveFallbackTargetSessionId?.(ctx) ?? null;
  const isSubagent =
    isSubagentExecutionContext(ctx, deps.subagentSessionsDir) ||
    (!ctx.hasUI && Boolean(fallbackTargetSessionId));
  const targetSessionId = resolvePermissionForwardingTargetSessionId({
    hasUI: ctx.hasUI,
    isSubagent,
    currentSessionId: requesterSessionId,
    env: process.env,
    fallbackTargetSessionId,
  });

  if (!targetSessionId) {
    logPermissionForwardingError(
      deps.logger,
      `Permission forwarding target session could not be resolved. ` +
        `Checked env vars: ${SUBAGENT_PARENT_SESSION_ENV_CANDIDATES.join(", ")}. ` +
        `If you are using a subagent extension (nicobailon/pi-subagents, HazAT/pi-interactive-subagents, etc.), ` +
        `ask its maintainer to set PI_SUBAGENT_PARENT_SESSION in the child process environment ` +
        `(see the subagent extension documentation).`,
    );
    return { approved: false, state: "denied" };
  }

  const location = ensurePermissionForwardingLocation(
    deps.logger,
    deps.forwardingDir,
    targetSessionId,
  );
  if (!location) {
    logPermissionForwardingError(
      deps.logger,
      `Permission forwarding is unavailable because session-scoped directories could not be prepared for '${targetSessionId}'`,
    );
    return { approved: false, state: "denied" };
  }

  const requestId = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}-${process.pid}`;
  const requesterAgentName =
    getActiveAgentName(ctx) ??
    getActiveAgentNameFromSystemPrompt(getContextSystemPrompt(ctx)) ??
    "unknown";
  const request: ForwardedPermissionRequest = {
    id: requestId,
    createdAt: Date.now(),
    requesterSessionId,
    targetSessionId,
    requesterAgentName,
    message,
    ...(requestMetadata?.toolName
      ? { toolName: requestMetadata.toolName }
      : {}),
    ...(requestMetadata?.command
      ? { command: requestMetadata.command }
      : {}),
    ...(requestMetadata?.forcePromptInYolo
      ? { forcePromptInYolo: true }
      : {}),
    ...(requestMetadata?.allowSession === false ? { allowSession: false } : {}),
  };

  const requestPath = join(location.requestsDir, `${requestId}.json`);
  const responsePath = join(location.responsesDir, `${requestId}.json`);
  const startedAt = Date.now();

  deps.writeReviewLog("forwarded_permission.request_created", {
    requestId,
    requesterAgentName,
    requesterSessionId: request.requesterSessionId,
    targetSessionId,
    requestPath,
    responsePath,
  });
  deps.logger.writeDebugLog("forwarded_permission.requested", {
    requestId,
    requesterAgentName,
    requesterSessionId: request.requesterSessionId,
    targetSessionId,
    toolName: request.toolName ?? null,
    commandPresent: Boolean(request.command),
    forcePromptInYolo: request.forcePromptInYolo === true,
  });

  try {
    writeJsonFileAtomic(deps.logger, requestPath, request);
  } catch (error) {
    logPermissionForwardingError(
      deps.logger,
      `Failed to write forwarded permission request '${requestPath}'`,
      error,
    );
    deps.logger.writeDebugLog("forwarded_permission.failed", {
      requestId,
      reason: "request_write_failed",
      latencyMs: Math.max(0, Date.now() - startedAt),
    });
    return { approved: false, state: "denied" };
  }

  const deadline = Date.now() + PERMISSION_FORWARDING_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (existsSync(responsePath)) {
      const response = readForwardedPermissionResponse(
        deps.logger,
        responsePath,
      );
      deps.writeReviewLog("forwarded_permission.response_received", {
        requestId,
        approved: response?.approved ?? null,
        state: response?.state ?? null,
        denialReason: response?.denialReason ?? null,
        responderSessionId: response?.responderSessionId ?? null,
        targetSessionId,
        responsePath,
      });
      deps.logger.writeDebugLog("forwarded_permission.resolved", {
        requestId,
        approved: response?.approved ?? null,
        state: response?.state ?? null,
        latencyMs: Math.max(0, Date.now() - startedAt),
        responsePresent: response !== null,
      });
      safeDeleteFile(
        deps.logger,
        responsePath,
        "forwarded permission response",
      );
      safeDeleteFile(deps.logger, requestPath, "forwarded permission request");
      cleanupPermissionForwardingLocationIfEmpty(deps.logger, location);
      return response ?? { approved: false, state: "denied" };
    }

    await sleep(PERMISSION_FORWARDING_POLL_INTERVAL_MS);
  }

  logPermissionForwardingWarning(
    deps.logger,
    `Timed out waiting for forwarded permission response '${responsePath}'`,
  );
  deps.writeReviewLog("forwarded_permission.response_timed_out", {
    requestId,
    requesterAgentName,
    targetSessionId,
    responsePath,
  });
  deps.logger.writeDebugLog("forwarded_permission.failed", {
    requestId,
    reason: "response_timeout",
    latencyMs: Math.max(0, Date.now() - startedAt),
  });
  safeDeleteFile(deps.logger, requestPath, "forwarded permission request");
  cleanupPermissionForwardingLocationIfEmpty(deps.logger, location);
  return { approved: false, state: "denied" };
}

export async function processForwardedPermissionRequests(
  ctx: ExtensionContext,
  deps: PermissionForwardingDeps,
): Promise<void> {
  if (!ctx.hasUI) {
    return;
  }

  const currentSessionId = getSessionId(ctx);
  const location = getExistingPermissionForwardingLocation(
    deps.forwardingDir,
    currentSessionId,
  );
  if (!location) {
    return;
  }

  const requestFiles = listRequestFiles(deps.logger, location.requestsDir);
  if (requestFiles.length === 0) {
    return;
  }

  for (const fileName of requestFiles) {
    const requestPath = join(location.requestsDir, fileName);
    const request = readForwardedPermissionRequest(deps.logger, requestPath);
    if (!request) {
      safeDeleteFile(
        deps.logger,
        requestPath,
        `${location.label} forwarded permission request`,
      );
      continue;
    }

    if (!isForwardedPermissionRequestForSession(request, currentSessionId)) {
      logPermissionForwardingWarning(
        deps.logger,
        `Ignoring forwarded permission request '${request.id}' because it targets session '${request.targetSessionId}' instead of '${currentSessionId}'`,
      );
      safeDeleteFile(
        deps.logger,
        requestPath,
        `${location.label} forwarded permission request`,
      );
      continue;
    }

    // Skip stale requests from dead subagent processes.
    // Prevents phantom permission dialogs on session resume after subagent termination.
    const requesterPid = extractPidFromRequestId(request.id);
    if (requesterPid !== null && !isProcessAlive(requesterPid)) {
      logPermissionForwardingWarning(
        deps.logger,
        `Removing stale forwarded permission request '${request.id}' from dead process ${requesterPid} (agent: '${request.requesterAgentName}')`,
      );
      deps.writeReviewLog("forwarded_permission.stale_request_cleaned", {
        requestId: request.id,
        source: location.label,
        requesterAgentName: request.requesterAgentName,
        requesterSessionId: request.requesterSessionId,
        targetSessionId: request.targetSessionId,
        requesterPid,
        requestAge: Date.now() - request.createdAt,
      });
      safeDeleteFile(
        deps.logger,
        requestPath,
        `stale ${location.label} forwarded permission request`,
      );
      continue;
    }

    const forwardedPermissionLogDetails = {
      requestId: request.id,
      source: location.label,
      requesterAgentName: request.requesterAgentName,
      requesterSessionId: request.requesterSessionId,
      targetSessionId: request.targetSessionId,
      requestPath,
    };

    let decision: PermissionPromptDecision = {
      approved: false,
      state: "denied",
    };
    if (!request.forcePromptInYolo && deps.shouldAutoApprove(request)) {
      deps.writeReviewLog(
        "forwarded_permission.auto_approved",
        forwardedPermissionLogDetails,
      );
      deps.logger.writeDebugLog("forwarded_permission.auto_approved", forwardedPermissionLogDetails);
      decision = { approved: true, state: "approved" };
    } else {
      deps.writeReviewLog(
        "forwarded_permission.prompted",
        forwardedPermissionLogDetails,
      );
      deps.logger.writeDebugLog("forwarded_permission.prompted", forwardedPermissionLogDetails);
      const promptToken = deps.promptWaitTracker?.begin(
        ctx,
        "Waiting for subagent permission approval",
      );
      try {
        decision = await deps.requestPermissionDecisionFromUi(
          ctx.ui,
          "Permission Required (Subagent)",
          formatForwardedPermissionPrompt(request),
          request.allowSession === false
            ? { allowSession: false, allowWorkspace: false, allowGlobal: false }
            : undefined,
        );
      } catch (error) {
        logPermissionForwardingError(
          deps.logger,
          "Failed to show forwarded permission confirmation dialog",
          error,
        );
        decision = { approved: false, state: "denied" };
      } finally {
        deps.promptWaitTracker?.end(ctx, promptToken);
      }
    }

    const responsePath = join(location.responsesDir, `${request.id}.json`);
    deps.writeReviewLog(
      decision.approved
        ? "forwarded_permission.approved"
        : "forwarded_permission.denied",
      {
        requestId: request.id,
        source: location.label,
        requesterAgentName: request.requesterAgentName,
        requesterSessionId: request.requesterSessionId,
        targetSessionId: request.targetSessionId,
        responsePath,
        resolution: decision.state,
        denialReason: decision.denialReason ?? null,
      },
    );
    deps.logger.writeDebugLog(
      decision.approved
        ? "forwarded_permission.approved"
        : "forwarded_permission.denied",
      {
        ...forwardedPermissionLogDetails,
        resolution: decision.state,
        denialReasonPresent: Boolean(decision.denialReason),
      },
    );
    try {
      writeJsonFileAtomic(deps.logger, responsePath, {
        approved: decision.approved,
        state: decision.state,
        denialReason: decision.denialReason,
        ...(decision.humanDecided ? { humanDecided: true as const } : {}),
        responderSessionId: currentSessionId,
        respondedAt: Date.now(),
      } satisfies ForwardedPermissionResponse);
    } catch (error) {
      logPermissionForwardingError(
        deps.logger,
        `Failed to write ${location.label} forwarded permission response '${responsePath}'`,
        error,
      );
      continue;
    }

    safeDeleteFile(
      deps.logger,
      requestPath,
      `${location.label} forwarded permission request`,
    );
  }

  cleanupPermissionForwardingLocationIfEmpty(deps.logger, location);
}

export async function confirmPermission(
  ctx: ExtensionContext,
  message: string,
  deps: PermissionForwardingDeps,
  options?: RequestPermissionOptions,
  requestMetadata?: Pick<
    ForwardedPermissionRequest,
    "toolName" | "command" | "forcePromptInYolo" | "allowSession"
  >,
): Promise<PermissionPromptDecision> {
  if (ctx.hasUI) {
    return deps.requestPermissionDecisionFromUi(
      ctx.ui,
      "Permission Required",
      message,
      options,
    );
  }

  const fallbackTargetSessionId = deps.resolveFallbackTargetSessionId?.(ctx) ?? null;
  const isSubagent =
    isSubagentExecutionContext(ctx, deps.subagentSessionsDir) ||
    (!ctx.hasUI && Boolean(fallbackTargetSessionId));
  if (!isSubagent) {
    return { approved: false, state: "denied" };
  }

  return waitForForwardedPermissionApproval(
    ctx,
    message,
    deps,
    {
      ...requestMetadata,
      ...(options?.allowSession === false ? { allowSession: false } : {}),
    },
  );
}
