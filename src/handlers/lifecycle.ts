import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

import type { PermissionSession } from "#src/permission-session";
import { PERMISSION_SYSTEM_STATUS_KEY } from "#src/status";

/** Minimal subset of SessionStartEvent used by this handler. */
interface SessionStartPayload {
  reason: string;
}

/** Minimal subset of ResourcesDiscoverEvent used by this handler. */
interface ResourcesDiscoverPayload {
  reason: string;
}

/**
 * Handles session lifecycle events: start, reload, and shutdown.
 *
 * Constructor deps:
 * - `session` — encapsulates all mutable session state
 * - `cleanupRpc` — unsubscribes RPC handlers on shutdown
 */
export class SessionLifecycleHandler {
  constructor(
    private readonly session: PermissionSession,
    private readonly cleanupRpc: () => void,
  ) {}

  handleSessionStart(
    event: SessionStartPayload,
    ctx: ExtensionContext,
  ): Promise<void> {
    const { session } = this;
    session.refreshConfig(ctx);
    session.resetForNewSession(ctx);
    session.logResolvedConfigPaths();

    const agentName = session.resolveAgentName(ctx);
    const policyIssues = session.getConfigIssues(agentName ?? undefined);
    for (const issue of policyIssues) {
      session.logger.warn(issue);
    }

    if (event.reason === "reload") {
      session.logger.debug("lifecycle.reload", {
        triggeredBy: "session_start",
        reason: event.reason,
        cwd: ctx.cwd,
      });
    }
    return Promise.resolve();
  }

  handleResourcesDiscover(event: ResourcesDiscoverPayload): Promise<void> {
    if (event.reason !== "reload") {
      return Promise.resolve();
    }

    const { session } = this;
    session.reload();
    session.logger.debug("lifecycle.reload", {
      triggeredBy: "resources_discover",
      reason: event.reason,
      cwd: session.getRuntimeContext()?.cwd ?? null,
    });
    return Promise.resolve();
  }

  handleSessionShutdown(): Promise<void> {
    const { session } = this;
    const ctx = session.getRuntimeContext();
    if (ctx) {
      ctx.ui.setStatus(PERMISSION_SYSTEM_STATUS_KEY, undefined);
    }
    session.shutdown();
    this.cleanupRpc();
    return Promise.resolve();
  }
}
