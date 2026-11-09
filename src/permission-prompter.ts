import {
  patternKeyFor,
  workspaceScope,
  type HumanAction,
} from "./auto-mode-decision-store";
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
import { decideAutoMode } from "./auto-mode-policy";
import { isReadOnlyBashChain, isReadOnlyBashDiagnostic } from "./bash-command-safety";
import { buildAutoModeText, type AutoModeClient } from "./auto-mode-client";
import type { AutoModeEvaluator, EvaluationSkipReason } from "./auto-mode-evaluator";
import type {
  PermissionPromptDecision,
  RequestPermissionOptions,
} from "./permission-dialog";
import {
  matchesBashAskPattern,
  isRemovalOnlyAsk,
  matchesYoloAskBashPattern,
  shouldAutoApprovePermissionState,
  yoloAskPatternsFor,
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
  /** False offers once or this-session grants only (no workspace/global). Used when a policy deny is overridden by the user. */
  allowPersist?: boolean;
  /** Set only after normal deterministic tool gates pass. */
  autoModeEligible?: boolean;
  /** Whether eligible request path is workspace-local. */
  autoModeWorkspaceLocal?: boolean;
  /** Every operand stays in the workspace, even when the text holds other path-like strings (yolo injection allowance). */
  autoModeTargetsWorkspace?: boolean;
  /** Caller-side sensitive-path result; absolute paths never cross this boundary. */
  autoModeHardRuleHit?: boolean;
  /** Classifier operation for eligible workspace files or sandboxed Bash. */
  autoModeOperation?: "read" | "list" | "write" | "edit" | "exec" | "tool";
  /** Prebuilt, privacy-scoped classifier input. */
  autoModeText?: string;
  /** Whether the content preview was truncated to the classifier limit. */
  autoModeTextTruncated?: boolean;
  /** True only when the Bash request will run inside SRT. */
  autoModeSandboxed?: boolean;
  /** Redacted inner Bash commands, classified one by one. */
  autoModeUnits?: string[];
  /** Inner Bash commands cannot all be read statically. */
  autoModeOpaque?: boolean;
  /** Relative path only; never an absolute path or raw input. */
  autoModeWorkspaceRelativePath?: string;
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
function autoModeUnitFields(details: PromptPermissionDetails): { units?: string[]; opaque?: boolean } {
  const units = details.autoModeUnits;
  return units?.length ? { units, opaque: details.autoModeOpaque === true } : {};
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
    ...(details.autoModeWorkspaceRelativePath
      ? { workspaceRelativePath: details.autoModeWorkspaceRelativePath }
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
  autoModeClient?: Pick<AutoModeClient, "evaluate">;
  autoModeEvaluator?: Pick<AutoModeEvaluator, "evaluate">;
  /** Label a stored model evaluation with the human decision (D16). */
  recordHumanDecision?: (evaluationId: string, action: HumanAction, ts: number) => void;
  /** Store workspace-scoped, hashed host Bash decisions; never store command text. */
  /** Wait until extension-managed auto assets are ready or startup failed. */
  waitForAutoModeStartup?: () => Promise<void>;
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
/** Classifier findings that still block in yolo; every other non-allow result is allowed. */
const YOLO_BLOCKING_REASONS: ReadonlySet<string> = new Set(["threat_not_benign", "injection_detected"]);

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

    // Yolo never opens a dialog: every request resolves to allow or block-with-reason.
    if (config.mode === "yolo") {
      return this.resolveYolo(config, details, yoloContext.forcePromptInYolo, ctx.cwd, startedAt);
    }

    const explicitlyForcedPrompt =
      details.forcePromptInYolo === true
      || (config.mode === "auto"
        && typeof details.command === "string"
        && matchesBashAskPattern(yoloAskPatternsFor(config), details.command));
    if (
      details.toolName === "bash"
      && details.autoModeWorkspaceLocal === true
      && details.autoModeHardRuleHit === false
      && !explicitlyForcedPrompt
      && typeof details.command === "string"
      && (isReadOnlyBashDiagnostic(details.command)
        || (Boolean(ctx.cwd) && isReadOnlyBashChain(details.command, ctx.cwd!)))
    ) {
      this.writeReviewEntry("permission_request.read_only_diagnostic_auto_allowed", {
        ...details,
        resolution: "read_only_diagnostic_auto_allowed",
        autoModeReason: "curated_read_only_diagnostic",
      });
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: true,
        resolution: "read_only_diagnostic_auto_allowed",
        latencyMs: Date.now() - startedAt,
      });
      return { approved: true, state: "approved", autoApproved: true };
    }

    // Forced prompts (rm, ssh, git push, publish, cluster writes, yoloAskBashPatterns) go to the model in auto;
    // only sensitive paths (hardRuleHit) and ineligible requests always prompt.
    const forced = yoloContext.forcePromptInYolo;
    const autoModeDecision = await this.evaluateAutoMode(
      config,
      forced ? { ...details, forcePromptInYolo: true } : details,
      ctx.cwd,
    );
    if (autoModeDecision.action === "allow") {
      this.writeReviewEntry("permission_request.auto_mode_approved", {
        ...details,
        autoModeReason: autoModeDecision.reason,
        evaluationId: autoModeDecision.evaluationId,
        autoModeAudit: autoModeDecision.audit,
      });
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: true,
        resolution: "auto_mode_approved",
        autoModeReason: autoModeDecision.reason,
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
              ...(details.allowPersist === false
                ? { allowWorkspace: false, allowGlobal: false }
                : { allowWorkspace: Boolean(ctx.cwd) }),
            },
        {
          toolName: details.toolName,
          command: details.command,
          forcePromptInYolo: yoloContext.forcePromptInYolo,
        },
      );

      // Only a person's explicit dialog answer is a learning label; failures and timeouts are not.
      if (decision.humanDecided && details.allowSession !== false) {
        this.labelEvaluation(autoModeDecision.evaluationId, decision.state, details);
      }

      this.writeReviewEntry(
        decision.approved
          ? "permission_request.approved"
          : "permission_request.denied",
        {
          ...details,
          resolution: decision.state,
          denialReason: decision.denialReason,
          evaluationId: autoModeDecision.evaluationId,
          autoModeAudit: autoModeDecision.audit,
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

  /**
   * Yolo resolution. Workspace calls, pathless tools and non-sensitive external reads pass; external writes and exec
   * go to the model, which can only block on a threat or injection finding. Forced prompts and sensitive external
   * reads block. Hard rules never reach this method.
   */
  private async resolveYolo(
    config: PermissionSystemExtensionConfig,
    details: PromptPermissionDetails,
    forced: boolean,
    cwd: string | undefined,
    startedAt: number,
  ): Promise<PermissionPromptDecision> {
    const block = (reason: string): PermissionPromptDecision => {
      const denialReason = `Blocked by yolo mode: ${reason}`;
      this.writeReviewEntry("permission_request.yolo_blocked", { ...details, resolution: "denied", denialReason });
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: false,
        resolution: "yolo_blocked",
        denialReason,
        latencyMs: Date.now() - startedAt,
      });
      return { approved: false, state: "denied", denialReason };
    };
    const allow = (event: string, audit: { autoModeReason?: string; evaluationId?: string; autoModeAudit?: boolean } = {}): PermissionPromptDecision => {
      this.writeReviewEntry(event, { ...details, ...audit });
      this.writeDebugPrompt("permission_prompt.resolved", details, {
        approved: true,
        resolution: event.replace("permission_request.", ""),
        autoModeReason: audit.autoModeReason ?? null,
        latencyMs: Date.now() - startedAt,
      });
      return { approved: true, state: "approved", autoApproved: true };
    };
    // rm stays allowed when every operand is inside the workspace and no hard rule hits.
    const workspaceRemoval = details.forcePromptInYolo !== true
      && typeof details.command === "string"
      && details.autoModeTargetsWorkspace === true
      && details.autoModeHardRuleHit === false
      && isRemovalOnlyAsk(details.command, config);
    if (forced && !workspaceRemoval) return block("this command needs explicit approval");
    const operation = details.autoModeOperation;
    const isExternal = details.autoModeWorkspaceLocal !== true;
    if (isExternal && (operation === "read" || operation === "list") && details.autoModeHardRuleHit !== false) {
      return block("sensitive path outside the workspace");
    }
    if (!(isExternal && (operation === "write" || operation === "edit" || operation === "exec"))) {
      return allow("permission_request.auto_approved");
    }

    const decision = await this.evaluateAutoMode(config, details, cwd, true);
    const audit = { autoModeReason: decision.reason, evaluationId: decision.evaluationId, autoModeAudit: decision.audit };
    if (decision.action === "allow") return allow("permission_request.auto_mode_approved", audit);
    // Operands inside the workspace and no network target: the sandbox bounds the rest, and token-handling code or
    // an npm install often scores as a threat or injection.
    const workspaceOnly = details.autoModeTargetsWorkspace === true;
    if (!workspaceOnly && YOLO_BLOCKING_REASONS.has(decision.reason)) return block(`the safety classifier flagged this call (${decision.reason})`);
    return allow("permission_request.yolo_allowed_unclassified", audit);
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

  private async evaluateAutoMode(
    config: PermissionSystemExtensionConfig,
    details: PromptPermissionDetails,
    cwd: string | undefined,
    classifyInYolo = false,
  ): Promise<{
    action: "allow" | "prompt";
    reason: string;
    evaluationId?: string;
    audit?: boolean;
  }> {
    const operation = details.autoModeOperation;
    if ((config.mode !== "auto" && !classifyInYolo) || !operation) {
      return { action: "prompt", reason: "disabled_or_ineligible" };
    }
    // Skips still reach the evaluator so each one is logged; the model is never called for them.
    const skipReason: EvaluationSkipReason | undefined = details.autoModeEligible ? undefined : "not_eligible";
    if (this.deps.autoModeEvaluator) {
      return this.deps.autoModeEvaluator.evaluate({
        flow: "permission",
        candidate: skipReason === undefined,
        ...(skipReason ? { skipReason } : {}),
        enabled: true,
        permissionState: "ask",
        source: details.source,
        eligible: details.autoModeEligible === true,
        forcedPrompt: details.forcePromptInYolo === true,
        workspaceLocal: details.autoModeWorkspaceLocal === true,
        operation,
        toolName: details.toolName ?? "unknown",
        hardRuleHit: details.autoModeHardRuleHit ?? true,
        sandboxed: details.autoModeSandboxed === true,
        ...(details.autoModeWorkspaceRelativePath
          ? { workspaceRelativePath: details.autoModeWorkspaceRelativePath }
          : {}),
        ...(details.autoModeText !== undefined
          ? {
              text: details.autoModeText,
              truncated: details.autoModeTextTruncated ?? false,
            }
          : {}),
        ...autoModeUnitFields(details),
        toolCallIdPresent: Boolean(details.toolCallId),
        ...(details.toolCallId ? { toolCallId: details.toolCallId } : {}),
        ...decisionStoreFields(details, cwd),
      });
    }
    if (skipReason) return { action: "prompt", reason: skipReason };
    if (!this.deps.autoModeClient || !details.autoModeEligible) {
      return { action: "prompt", reason: "not_configured_or_ineligible" };
    }

    try {
      await this.deps.waitForAutoModeStartup?.();
    } catch {
      return { action: "prompt", reason: "startup_failed" };
    }
    const result = await this.deps.autoModeClient.evaluate(details.autoModeText ?? buildAutoModeText({
      toolName: details.toolName ?? "unknown",
      operation,
      ...(details.autoModeWorkspaceRelativePath
        ? { workspaceRelativePath: details.autoModeWorkspaceRelativePath }
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
      ...decideAutoMode({
        enabled: config.mode === "auto" || classifyInYolo,
        permissionState: "ask",
        source: details.source,
        hardRuleHit: details.autoModeHardRuleHit ?? true,
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
      autoModeReason?: string;
      evaluationId?: string;
      autoModeAudit?: boolean;
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
      autoModeEligible: details.autoModeEligible ?? false,
      autoModeOperation: details.autoModeOperation ?? null,
      autoModeWorkspaceRelativePath: details.autoModeWorkspaceRelativePath ?? null,
      autoModeReason: details.autoModeReason ?? null,
      ...(details.evaluationId !== undefined ? { evaluationId: details.evaluationId } : {}),
      ...(details.autoModeAudit !== undefined ? { autoModeAudit: details.autoModeAudit } : {}),
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
