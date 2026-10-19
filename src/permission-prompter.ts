import {
  patternKeyFor,
  workspaceScope,
  type HumanAction,
} from "./yolo-auto-decision-store";
import type { PermissionDecisionState } from "./permission-dialog";
import { createHash } from "node:crypto";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { PermissionSystemExtensionConfig } from "./extension-config";
import type { ForwardedPermissionLogger } from "./forwarded-permissions/io";
import {
  confirmPermission,
  type PermissionForwardingDeps,
} from "./forwarded-permissions/polling";
import { PromptWaitTracker } from "./prompt-state";
import { decideYoloAuto } from "./yolo-auto-policy";
import { isReadOnlyBashChain, isReadOnlyBashDiagnostic } from "./bash-command-safety";
import { buildYoloAutoText, type YoloAutoClient } from "./yolo-auto-client";
import type { YoloAutoEvaluator } from "./yolo-auto-evaluator";
import type {
  PermissionPromptDecision,
  RequestPermissionOptions,
} from "./permission-dialog";
import {
  matchesBashAskPattern,
  matchesYoloAskBashPattern,
  shouldAutoApprovePermissionState,
} from "./yolo-mode";

export type PermissionReviewSource = "tool_call" | "skill_input" | "skill_read";

/** Details passed when prompting the user for a permission decision. */
export interface PromptPermissionDetails {
  requestId: string;
  source: PermissionReviewSource;
  agentName: string | null;
  message: string;
  toolCallId?: string;
  toolName?: string;
  skillName?: string;
  path?: string;
  command?: string;
  target?: string;
  toolInputPreview?: string;
  forcePromptInYolo?: boolean;
  /** Override label for the "for this session" dialog option. */
  sessionLabel?: string;
  /** Disable all remembered approval choices for one-time prompts. */
  allowSession?: boolean;
  /** Set only after normal deterministic tool gates pass. */
  yoloAutoEligible?: boolean;
  /** Whether eligible request path is workspace-local. */
  yoloAutoWorkspaceLocal?: boolean;
  /** Caller-side sensitive-path result; absolute paths never cross this boundary. */
  yoloAutoHardRuleHit?: boolean;
  /** Classifier operation for eligible workspace files or sandboxed Bash. */
  yoloAutoOperation?: "read" | "list" | "write" | "edit" | "exec";
  /** Prebuilt, privacy-scoped classifier input. */
  yoloAutoText?: string;
  /** Whether the content preview was truncated to the classifier limit. */
  yoloAutoTextTruncated?: boolean;
  /** True only when the Bash request will run inside SRT. */
  yoloAutoSandboxed?: boolean;
  /** Redacted inner Bash commands, classified one by one. */
  yoloAutoUnits?: string[];
  /** Inner Bash commands cannot all be read statically. */
  yoloAutoOpaque?: boolean;
  /** Relative path only; never an absolute path or raw input. */
  yoloAutoWorkspaceRelativePath?: string;
}

/** Mockable contract for permission prompting. */
export interface PermissionPrompterApi {
  prompt(
    ctx: ExtensionContext,
    details: PromptPermissionDetails,
  ): Promise<PermissionPromptDecision>;
}

/**
 * Dependencies required by PermissionPrompter.
 *
 * Keeps the prompter's external surface narrow: callers provide config
 * access, review-log writing, path constants, and the UI dialog function.
 * The prompter synthesises the PermissionForwardingDeps it needs internally.
 */
const HUMAN_ACTION_BY_STATE: Record<PermissionDecisionState, HumanAction> = {
  approved: "allow_once",
  approved_for_session: "session",
  approved_for_workspace: "workspace",
  approved_globally: "global",
  denied: "deny",
  denied_with_reason: "deny",
};

/** Inner Bash commands for per-command classification; omitted when the command could not be split. */
function yoloAutoUnitFields(details: PromptPermissionDetails): { units?: string[]; opaque?: boolean } {
  const units = details.yoloAutoUnits;
  return units?.length ? { units, opaque: details.yoloAutoOpaque === true } : {};
}

/** Scope and coarse pattern key for the decision store; omitted without a workspace. */
function decisionStoreFields(
  details: PromptPermissionDetails,
  cwd: string | undefined,
): { scope?: string; patternKey?: string } {
  if (!cwd) return {};
  const patternKey = patternKeyFor({
    toolName: details.toolName ?? "unknown",
    ...(details.command ? { command: details.command } : {}),
    ...(details.yoloAutoWorkspaceRelativePath
      ? { workspaceRelativePath: details.yoloAutoWorkspaceRelativePath }
      : {}),
  });
  return { scope: workspaceScope(cwd), ...(patternKey ? { patternKey } : {}) };
}

export interface PermissionPrompterDeps {
  promptWaitTracker: PromptWaitTracker;
  /** Read current config for yolo-mode check (called at prompt time). */
  getConfig(): PermissionSystemExtensionConfig;
  /** Write structured entries to the permission review log. */
  writeReviewLog(event: string, details: Record<string, unknown>): void;
  /** Write privacy-safe diagnostic entries when debug logging is enabled. */
  writeDebugLog?: (event: string, details: Record<string, unknown>) => void;
  /** Directory containing subagent session state. */
  subagentSessionsDir: string;
  /** Directory used for file-based permission forwarding requests/responses. */
  forwardingDir: string;
  /** Optional fallback resolver for parent session id when subagent env markers are absent. */
  resolveFallbackTargetSessionId?: (ctx: ExtensionContext) => string | null;
  /** Optional shared worker client; absent/unavailable always falls back to prompt. */
  yoloAutoClient?: Pick<YoloAutoClient, "evaluate">;
  yoloAutoEvaluator?: Pick<YoloAutoEvaluator, "evaluate">;
  /** Label a stored model evaluation with the human decision (D16). */
  recordHumanDecision?: (evaluationId: string, action: HumanAction, ts: number) => void;
  /** Store workspace-scoped, hashed host Bash decisions; never store command text. */
  /** Wait until extension-managed yolo-auto assets are ready or startup failed. */
  waitForYoloAutoStartup?: () => Promise<void>;
  /** Show the interactive permission dialog in the UI. */
  requestPermissionDecisionFromUi(
    ui: ExtensionContext["ui"],
    title: string,
    message: string,
    options?: RequestPermissionOptions,
  ): Promise<PermissionPromptDecision>;
}

/**
 * Encapsulates the full permission-prompt flow:
 *   1. Yolo-mode auto-approval check.
 *   2. Review-log "waiting" entry.
 *   3. UI-present vs. subagent-forwarding branching (via confirmPermission).
 *   4. Review-log "approved" / "denied" entry.
 *
 * Injecting a single PermissionPrompter instance means adding a new prompt
 * parameter (e.g. a future sessionLabel variant) only requires changing
 * PromptPermissionDetails and this class — not the full threading chain.
 */
export class PermissionPrompter implements PermissionPrompterApi {
  constructor(private readonly deps: PermissionPrompterDeps) {}

  async prompt(
    ctx: ExtensionContext,
    details: PromptPermissionDetails,
  ): Promise<PermissionPromptDecision> {
    const startedAt = Date.now();
    const config = this.deps.getConfig();
    this.writeDebugPrompt("permission_prompt.requested", details);
    const yoloContext = {
      toolName: details.toolName,
      command: details.command,
      forcePromptInYolo:
        details.forcePromptInYolo === true
        || matchesYoloAskBashPattern(
          {
            toolName: details.toolName,
            command: details.command,
          },
          config,
        ),
    };

    // YoloAuto approves only model-eligible requests; classic YOLO keeps its broad bypass.
    const yoloAutoCandidate =
      config.mode === "yolo-auto"
      && details.yoloAutoEligible === true
      && details.yoloAutoWorkspaceLocal === true
      && Boolean(details.yoloAutoOperation);
    if (config.mode === "yolo"
      && shouldAutoApprovePermissionState("ask", config, yoloContext)
      && !yoloAutoCandidate) {
      this.writeReviewEntry("permission_request.auto_approved", details);
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: true,
        resolution: "auto_approved",
        latencyMs: Date.now() - startedAt,
      });
      return { approved: true, state: "approved", autoApproved: true };
    }

    const explicitlyForcedPrompt =
      details.forcePromptInYolo === true
      || ((config.mode === "yolo" || config.mode === "yolo-auto")
        && typeof details.command === "string"
        && matchesBashAskPattern(config.yoloAskBashPatterns ?? [], details.command));
    if (
      details.toolName === "bash"
      && details.yoloAutoWorkspaceLocal === true
      && details.yoloAutoHardRuleHit === false
      && !explicitlyForcedPrompt
      && typeof details.command === "string"
      && (isReadOnlyBashDiagnostic(details.command)
        || (Boolean(ctx.cwd) && isReadOnlyBashChain(details.command, ctx.cwd!)))
    ) {
      this.writeReviewEntry("permission_request.read_only_diagnostic_auto_allowed", {
        ...details,
        resolution: "read_only_diagnostic_auto_allowed",
        yoloAutoReason: "curated_read_only_diagnostic",
      });
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: true,
        resolution: "read_only_diagnostic_auto_allowed",
        latencyMs: Date.now() - startedAt,
      });
      return { approved: true, state: "approved", autoApproved: true };
    }

    const yoloAutoDecision = await this.evaluateYoloAuto(config, details, ctx.cwd);
    if (yoloAutoDecision.action === "allow") {
      this.writeReviewEntry("permission_request.yolo_auto_approved", {
        ...details,
        yoloAutoReason: yoloAutoDecision.reason,
        evaluationId: yoloAutoDecision.evaluationId,
        yoloAutoAudit: yoloAutoDecision.audit,
      });
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: true,
        resolution: "yolo_auto_approved",
        yoloAutoReason: yoloAutoDecision.reason,
        latencyMs: Date.now() - startedAt,
      });
      return { approved: true, state: "approved", autoApproved: true };
    }

    this.writeReviewEntry("permission_request.waiting", details);

    const promptToken = this.deps.promptWaitTracker.begin(
      ctx,
      "Waiting for permission approval",
    );

    try {
      const decision = await confirmPermission(
        ctx,
        details.message,
        this.buildForwardingDeps(),
        details.allowSession === false
          ? { allowSession: false, allowWorkspace: false, allowGlobal: false }
          : {
              ...(details.sessionLabel ? { sessionLabel: details.sessionLabel } : {}),
              allowWorkspace: Boolean(ctx.cwd),
            },
        {
          toolName: details.toolName,
          command: details.command,
          forcePromptInYolo: yoloContext.forcePromptInYolo,
        },
      );

      // Only a person's explicit dialog answer is a learning label; failures and timeouts are not.
      if (decision.humanDecided && details.allowSession !== false) {
        this.labelEvaluation(yoloAutoDecision.evaluationId, decision.state, details);
      }

      this.writeReviewEntry(
        decision.approved
          ? "permission_request.approved"
          : "permission_request.denied",
        {
          ...details,
          resolution: decision.state,
          denialReason: decision.denialReason,
          evaluationId: yoloAutoDecision.evaluationId,
          yoloAutoAudit: yoloAutoDecision.audit,
        },
      );
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: decision.approved,
        resolution: decision.state,
        denialReason: decision.denialReason ?? null,
        latencyMs: Date.now() - startedAt,
      });

      return decision;
    } catch (error) {
      this.writeDebugPrompt("permission_prompt.failed", details, {
        errorName: error instanceof Error ? error.name : "UnknownError",
        latencyMs: Date.now() - startedAt,
      });
      throw error;
    } finally {
      this.deps.promptWaitTracker.end(ctx, promptToken);
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  /** Label the stored model evaluation with the human decision (D16). */
  private labelEvaluation(
    evaluationId: string | undefined,
    state: PermissionDecisionState,
    details: PromptPermissionDetails,
  ): void {
    if (!evaluationId || !this.deps.recordHumanDecision) return;
    try {
      this.deps.recordHumanDecision(evaluationId, HUMAN_ACTION_BY_STATE[state], Date.now());
    } catch (error) {
      this.writeDebugPrompt("permission_prompt.decision_store_failed", details, {
        errorName: error instanceof Error ? error.name : "UnknownError",
      });
    }
  }

  private async evaluateYoloAuto(
    config: PermissionSystemExtensionConfig,
    details: PromptPermissionDetails,
    cwd: string | undefined,
  ): Promise<{
    action: "allow" | "prompt";
    reason: string;
    evaluationId?: string;
    audit?: boolean;
  }> {
    const operation = details.yoloAutoOperation;
    if (config.mode !== "yolo-auto" || !operation || !details.yoloAutoWorkspaceLocal) {
      return { action: "prompt", reason: "disabled_or_ineligible" };
    }
    if (!details.yoloAutoEligible) {
      return { action: "prompt", reason: "not_configured_or_ineligible" };
    }
    if (this.deps.yoloAutoEvaluator) {
      return this.deps.yoloAutoEvaluator.evaluate({
        flow: "permission",
        candidate: true,
        enabled: true,
        permissionState: "ask",
        source: details.source,
        eligible: details.yoloAutoEligible === true,
        forcedPrompt: details.forcePromptInYolo === true,
        workspaceLocal: details.yoloAutoWorkspaceLocal === true,
        operation,
        toolName: details.toolName ?? "unknown",
        hardRuleHit: details.yoloAutoHardRuleHit ?? true,
        sandboxed: details.yoloAutoSandboxed === true,
        ...(details.yoloAutoWorkspaceRelativePath
          ? { workspaceRelativePath: details.yoloAutoWorkspaceRelativePath }
          : {}),
        ...(details.yoloAutoText !== undefined
          ? {
              text: details.yoloAutoText,
              truncated: details.yoloAutoTextTruncated ?? false,
            }
          : {}),
        ...yoloAutoUnitFields(details),
        toolCallIdPresent: Boolean(details.toolCallId),
        ...(details.toolCallId ? { toolCallId: details.toolCallId } : {}),
        ...decisionStoreFields(details, cwd),
      });
    }
    if (!this.deps.yoloAutoClient || !details.yoloAutoEligible) {
      return { action: "prompt", reason: "not_configured_or_ineligible" };
    }

    try {
      await this.deps.waitForYoloAutoStartup?.();
    } catch {
      return { action: "prompt", reason: "startup_failed" };
    }
    const result = await this.deps.yoloAutoClient.evaluate(details.yoloAutoText ?? buildYoloAutoText({
      toolName: details.toolName ?? "unknown",
      operation,
      ...(details.yoloAutoWorkspaceRelativePath
        ? { workspaceRelativePath: details.yoloAutoWorkspaceRelativePath }
        : {}),
    }));
    if (result.status === "unavailable") {
      return {
        action: "prompt",
        reason: result.reason,
        evaluationId: result.evaluationId,
        audit: false,
      };
    }
    return {
      ...decideYoloAuto({
        enabled: config.mode === "yolo-auto",
        permissionState: "ask",
        source: details.source,
        eligible: details.yoloAutoEligible === true,
        forcedPrompt: details.forcePromptInYolo === true,
        workspaceLocal: details.yoloAutoWorkspaceLocal === true,
        hardRuleHit: details.yoloAutoHardRuleHit ?? true,
        sandboxed: false,
        operation,
        toolName: details.toolName ?? "unknown",
        heads: result.heads,
      }),
      evaluationId: result.evaluationId,
      audit: false,
    };
  }

  private writeDebugPrompt(
    event: string,
    details: PromptPermissionDetails,
    extra: Record<string, unknown> = {},
  ): void {
    this.deps.writeDebugLog?.(event, {
      requestId: details.requestId,
      source: details.source,
      agentName: details.agentName,
      toolCallId: details.toolCallId ?? null,
      toolName: details.toolName ?? null,
      pathPresent: Boolean(details.path),
      commandPresent: Boolean(details.command),
      targetPresent: Boolean(details.target),
      messageLength: details.message.length,
      messageHash: createHash("sha256").update(details.message).digest("hex").slice(0, 16),
      ...extra,
    });
  }

  private writeReviewEntry(
    event: string,
    details: PromptPermissionDetails & {
      resolution?: string;
      denialReason?: string;
      yoloAutoReason?: string;
      evaluationId?: string;
      yoloAutoAudit?: boolean;
    },
  ): void {
    this.deps.writeReviewLog(event, {
      requestId: details.requestId,
      source: details.source,
      agentName: details.agentName,
      message: details.message,
      toolCallId: details.toolCallId ?? null,
      toolName: details.toolName ?? null,
      skillName: details.skillName ?? null,
      path: details.path ?? null,
      command: details.command ?? null,
      target: details.target ?? null,
      toolInputPreview: details.toolInputPreview ?? null,
      yoloAutoEligible: details.yoloAutoEligible ?? false,
      yoloAutoOperation: details.yoloAutoOperation ?? null,
      yoloAutoWorkspaceRelativePath: details.yoloAutoWorkspaceRelativePath ?? null,
      yoloAutoReason: details.yoloAutoReason ?? null,
      ...(details.evaluationId !== undefined ? { evaluationId: details.evaluationId } : {}),
      ...(details.yoloAutoAudit !== undefined ? { yoloAutoAudit: details.yoloAutoAudit } : {}),
      resolution: details.resolution ?? null,
      denialReason: details.denialReason ?? null,
    });
  }

  /**
   * Build a PermissionForwardingDeps to pass to confirmPermission.
   *
   * Yolo-mode is already handled at the prompter level, so shouldAutoApprove
   * returns false here (confirmPermission does not call it; only
   * processForwardedPermissionRequests does, and that has its own deps).
   *
   * The logger delegates writeReviewLog to deps and uses a no-op writeDebugLog
   * Debug forwarding entries use the same privacy-safe logger as prompts.
   */
  private buildForwardingDeps(): PermissionForwardingDeps {
    const { deps } = this;
    const logger: ForwardedPermissionLogger = {
      // eslint-disable-next-line @typescript-eslint/unbound-method -- logger methods are plain function closures; no this-binding issue
      writeReviewLog: deps.writeReviewLog,
      // eslint-disable-next-line @typescript-eslint/unbound-method -- logger is a plain function closure
      writeDebugLog: deps.writeDebugLog ?? (() => undefined),
    };
    return {
      forwardingDir: deps.forwardingDir,
      subagentSessionsDir: deps.subagentSessionsDir,
      logger,
      // eslint-disable-next-line @typescript-eslint/unbound-method -- logger methods are plain function closures; no this-binding issue
      writeReviewLog: deps.writeReviewLog,
      // eslint-disable-next-line @typescript-eslint/unbound-method -- same as above
      requestPermissionDecisionFromUi: deps.requestPermissionDecisionFromUi,
      shouldAutoApprove: () => false,
      resolveFallbackTargetSessionId: deps.resolveFallbackTargetSessionId,
    };
  }
}
