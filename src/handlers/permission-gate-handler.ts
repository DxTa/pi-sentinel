
import { matchTrustedPiRequest } from "./gates/trusted-pi-dirs";
import { READ_ONLY_PATH_BEARING_TOOLS } from "#src/path-utils";
import type {
  ExtensionContext,
  InputEventResult,
} from "@earendil-works/pi-coding-agent";

import { getNonEmptyString, toRecord } from "#src/common";
import {
  getPathBearingToolPath,
  isPathOutsideWorkingDirectory,
  isWorkspaceLocalFileOperation,
  normalizePathForComparison,
} from "#src/path-utils";
import { suggestSessionPattern } from "#src/pattern-suggest";

import {
  emitDecisionEvent,
  type PermissionEventBus,
} from "#src/permission-events";
import { applyPermissionGate } from "#src/permission-gate";
import type { PromptPermissionDetails } from "#src/permission-prompter";
import {
  formatMissingToolNameReason,
  formatSkillAskPrompt,
  formatUnknownToolReason,
} from "#src/permission-prompts";
import type { PermissionSession } from "#src/permission-session";
import {
  checkRequestedToolRegistration,
  getToolNameFromValue,
  type ToolRegistry,
} from "#src/tool-registry";
import { buildYoloAutoBashContext } from "#src/yolo-auto-bash-context";
import { shouldRelaxBundledToolDenyInYolo } from "#src/yolo-mode";
import { describeBashExternalDirectoryGate } from "./gates/bash-external-directory";

import { describeBashPathGate } from "./gates/bash-path";
import { extractTokensForPathRules } from "./gates/bash-path-extractor";
import type { GateRunnerDeps } from "./gates/descriptor";
import { isGateBypass } from "./gates/descriptor";
import { describeExternalDirectoryGate } from "./gates/external-directory";
import { describePathGate } from "./gates/path";
import { runGateCheck } from "./gates/runner";
import { describeSkillReadGate } from "./gates/skill-read";
import { describeToolGate } from "./gates/tool";
import type { ToolCallContext } from "./gates/types";

/** Minimal subset of InputEvent used by handleInput. */
interface InputPayload {
  text: string;
}

interface PermissionGateHandlerOptions {
  isTrustedClipboardReadPath?: (pathValue: string) => boolean;
}

/**
 * Handles permission gate events: tool_call and input.
 *
 * Constructor deps:
 * - `session` — encapsulates all mutable session state and permission operations
 * - `events` — event bus for emitting permissions:decision broadcasts
 * - `toolRegistry` — Pi tool API subset (getAll + setActive)
 */
export class PermissionGateHandler {
  constructor(
    private readonly session: PermissionSession,
    private readonly events: PermissionEventBus,
    private readonly toolRegistry: ToolRegistry,
    private readonly options: PermissionGateHandlerOptions = {},
  ) {}

  async handleToolCall(
    event: unknown,
    ctx: ExtensionContext,
    sandboxedForYoloAuto = false,
  ): Promise<{ block?: true; reason?: string }> {
    const { session } = this;
    session.activate(ctx);

    const agentName = session.resolveAgentName(ctx);
    const toolName = getToolNameFromValue(event);

    if (!toolName) {
      return { block: true, reason: formatMissingToolNameReason() };
    }

    const registrationCheck = checkRequestedToolRegistration(
      toolName,
      this.toolRegistry.getAll(),
    );
    if (registrationCheck.status === "missing-tool-name") {
      return { block: true, reason: formatMissingToolNameReason() };
    }

    if (registrationCheck.status === "unregistered") {
      return {
        block: true,
        reason: formatUnknownToolReason(
          registrationCheck.requestedToolName,
          registrationCheck.availableToolNames,
        ),
      };
    }

    const input = getEventInput(event);
    const toolCallId =
      typeof (event as Record<string, unknown>).toolCallId === "string"
        ? ((event as Record<string, unknown>).toolCallId as string)
        : "";

    const tcc: ToolCallContext = {
      toolName,
      agentName,
      input,
      toolCallId,
      cwd: ctx.cwd,
      sandboxed: sandboxedForYoloAuto,
    };

    session.logger.debug("tool_call.received", {
      source: "tool_call",
      toolCallId,
      toolName,
      agentName,
      pathPresent: Boolean(getPathBearingToolPath(toolName, input)),
    });

    // ── Shared gate adapter closures ─────────────────────────────────────
    const canConfirm: GateRunnerDeps["canConfirm"] = (details) =>
      session.canPrompt(ctx, details);
    const promptPermission = (details: PromptPermissionDetails) =>
      session.prompt(ctx, details);
    const emitDecision: GateRunnerDeps["emitDecision"] = (e) =>
      emitDecisionEvent(this.events, e);
    // eslint-disable-next-line @typescript-eslint/unbound-method -- logger.review is a plain function closure; no this-binding issue
    const writeReviewLog = session.logger.review;
    const checkPermission: GateRunnerDeps["checkPermission"] = (
      surface,
      input,
      agent,
      sessionRules,
    ) => session.checkPermission(surface, input, agent, sessionRules);
    const getSessionRuleset = () => session.getSessionRuleset();
    const approveSessionRule = (surface: string, pattern: string) =>
      session.approveSessionRule(surface, pattern);
    const persistPermissionRule: GateRunnerDeps["persistPermissionRule"] = (
      scope,
      surface,
      pattern,
    ) => session.persistPermissionRule(scope, surface, pattern);

    // ── Shared runner deps (built once, reused for all gates) ────────────
    const runnerDeps: GateRunnerDeps = {
      checkPermission,
      getSessionRuleset,
      approveSessionRule,
      persistPermissionRule,
      writeReviewLog,
      writeDebugLog: session.logger.debug,
      emitDecision,
      canConfirm,
      promptPermission,
    };

    // ── Trusted Pi dirs: reads + single-script runs, in every mode ──────────
    const trusted = tcc.cwd
      ? matchTrustedPiRequest(tcc.toolName, tcc.input, tcc.cwd, session.getTrustedPiDirs())
      : null;
    if (
      trusted
      && checkPermission(tcc.toolName, tcc.input, tcc.agentName ?? undefined, getSessionRuleset()).state !== "deny"
    ) {
      writeReviewLog("permission_request.trusted_pi_auto_allowed", {
        source: "tool_call",
        toolCallId: tcc.toolCallId,
        toolName: tcc.toolName,
        agentName: tcc.agentName,
        kind: trusted.kind,
        path: trusted.path,
      });
      emitDecision({
        surface: tcc.toolName,
        value: trusted.path,
        result: "allow",
        resolution: "infrastructure_auto_allowed",
        origin: null,
        agentName: tcc.agentName ?? null,
        matchedPattern: null,
      });
      return {};
    }

    // ── Skill-read gate (descriptor + runner) ───────────────────────────────
    const skillDescriptor = describeSkillReadGate(tcc, () =>
      session.getActiveSkillEntries(),
    );
    if (skillDescriptor) {
      const skillResult = await runGateCheck(
        skillDescriptor,
        tcc.agentName,
        tcc.toolCallId,
        runnerDeps,
      );
      if (skillResult.action === "block") {
        return { block: true, reason: skillResult.reason };
      }
    }

    // ── Path gate for tools (descriptor + runner) ────────────────────────────
    const pathDesc = describePathGate(
      tcc,
      checkPermission,
      getSessionRuleset,
    );
    if (pathDesc) {
      if (isGateBypass(pathDesc)) {
        if (pathDesc.log) {
          writeReviewLog(pathDesc.log.event, pathDesc.log.details);
        }
      } else {
        const pathResult = await runGateCheck(
          pathDesc,
          tcc.agentName,
          tcc.toolCallId,
          runnerDeps,
        );
        if (pathResult.action === "block") {
          return { block: true, reason: pathResult.reason };
        }
      }
    }

    // ── External-directory gate (descriptor + runner) ────────────────────────
    const infraDirs = [
      ...session.getInfrastructureDirs(),
      ...session.getInfrastructureReadPaths(),
    ];
    const extDirDesc = describeExternalDirectoryGate(
      tcc,
      infraDirs,
      this.options.isTrustedClipboardReadPath,
    );
    if (extDirDesc) {
      if (isGateBypass(extDirDesc)) {
        if (extDirDesc.log) {
          writeReviewLog(extDirDesc.log.event, extDirDesc.log.details);
        }
        if (extDirDesc.decision) {
          emitDecision(extDirDesc.decision);
        }
      } else {
        const extDirResult = await runGateCheck(
          extDirDesc,
          tcc.agentName,
          tcc.toolCallId,
          runnerDeps,
        );
        if (extDirResult.action === "block") {
          return { block: true, reason: extDirResult.reason };
        }
      }
    }

    const workspaceLocalFileOperation = Boolean(
      tcc.cwd
      && isWorkspaceLocalFileOperation(tcc.toolName, tcc.input, tcc.cwd)
    );

    // ── Bash external-directory gate (descriptor + runner) ───────────────────
    const bashExtDesc = await describeBashExternalDirectoryGate(
      tcc,
      checkPermission,
      getSessionRuleset,
    );
    if (bashExtDesc) {
      if (isGateBypass(bashExtDesc)) {
        if (bashExtDesc.log) {
          writeReviewLog(bashExtDesc.log.event, bashExtDesc.log.details);
        }
      } else {
        const bashExtResult = await runGateCheck(
          bashExtDesc,
          tcc.agentName,
          tcc.toolCallId,
          runnerDeps,
        );
        if (bashExtResult.action === "block") {
          return { block: true, reason: bashExtResult.reason };
        }
      }
    }

    // ── Bash path gate (descriptor + runner) ────────────────────────────────
    const bashCommand = tcc.toolName === "bash"
      ? getNonEmptyString(toRecord(tcc.input).command)
      : null;
    const bashPathTokens = bashCommand !== null
      ? await extractTokensForPathRules(bashCommand)
      : undefined;
    const yoloAutoBashContext = bashPathTokens !== undefined && bashCommand !== null
      ? buildYoloAutoBashContext(bashCommand, bashPathTokens, tcc.cwd)
      : undefined;
    const toolTcc = yoloAutoBashContext === undefined
      ? tcc
      : {
          ...tcc,
          yoloAutoHardRuleHit: yoloAutoBashContext.hardRuleHit,
          yoloAutoWorkspaceLocal: yoloAutoBashContext.workspaceLocal,
          yoloAutoCommand: yoloAutoBashContext.command,
        };
    const bashPathDesc = await describeBashPathGate(
      toolTcc,
      checkPermission,
      getSessionRuleset,
      bashPathTokens,
    );

    if (bashPathDesc) {
      if (isGateBypass(bashPathDesc)) {
        if (bashPathDesc.log) {
          writeReviewLog(bashPathDesc.log.event, bashPathDesc.log.details);
        }
      } else {
        const bashPathResult = await runGateCheck(
          bashPathDesc,
          tcc.agentName,
          tcc.toolCallId,
          runnerDeps,
        );
        if (bashPathResult.action === "block") {
          return { block: true, reason: bashPathResult.reason };
        }
      }
    }

    // ── Normal tool permission gate (descriptor + runner) ────────────────────
    const toolSessionRules = getSessionRuleset();
    const toolPath = getPathBearingToolPath(tcc.toolName, tcc.input);
    const normalizedExternalToolPath =
      toolPath && tcc.cwd && isPathOutsideWorkingDirectory(toolPath, tcc.cwd)
        ? normalizePathForComparison(toolPath, tcc.cwd)
        : null;
    const hasExternalDirectoryApproval =
      normalizedExternalToolPath !== null
      && checkPermission(
        "external_directory",
        { path: normalizedExternalToolPath },
        tcc.agentName ?? undefined,
        toolSessionRules,
      ).state === "allow";
    const baseToolCheck = checkPermission(
      tcc.toolName,
      tcc.input,
      tcc.agentName ?? undefined,
      toolSessionRules,
    );
    const toolCheck = shouldRelaxBundledToolDenyInYolo({
      config: session.config,
      toolName: tcc.toolName,
      path: toolPath,
      cwd: tcc.cwd,
      toolPermission: baseToolCheck,
      hasExternalDirectoryApproval,
    })
      ? { ...baseToolCheck, state: "ask" as const }
      : baseToolCheck;

    // Let YoloAuto classify workspace operations only when normal policy asks.
    // Workspace reads never need the model; writes still go through YoloAuto when policy asks.
    if (
      workspaceLocalFileOperation
      && (session.config.mode !== "yolo-auto"
        || toolCheck.state !== "ask"
        || READ_ONLY_PATH_BEARING_TOOLS.has(tcc.toolName)
        || tcc.toolName === "ls")
    ) {
      session.logger.debug("permission_gate.resolved", {
        source: "tool_call",
        toolCallId,
        toolName,
        agentName,
        action: "allow",
        resolution: "workspace_auto_allowed",
        workspaceLocal: true,
      });
      return {};
    }

    const toolDescriptor = describeToolGate(toolTcc, toolCheck);
    toolDescriptor.preCheck = toolCheck;

    const toolResult = await runGateCheck(
      toolDescriptor,
      tcc.agentName,
      tcc.toolCallId,
      runnerDeps,
    );
    if (toolResult.action === "block") {
      return { block: true, reason: toolResult.reason };
    }

    return {};
  }

  async handleInput(
    event: InputPayload,
    ctx: ExtensionContext,
  ): Promise<InputEventResult> {
    const { session } = this;
    session.activate(ctx);

    const skillName = extractSkillNameFromInput(event.text);
    if (!skillName) {
      return { action: "continue" };
    }

    const agentName = session.resolveAgentName(ctx);
    const check = session.checkPermission(
      "skill",
      { name: skillName },
      agentName ?? undefined,
    );

    if (check.state === "deny" && ctx.hasUI) {
      const notifyMessage = agentName
        ? `Skill '${skillName}' is not permitted for agent '${agentName}'.`
        : `Skill '${skillName}' is not permitted by the current skill policy.`;
      ctx.ui.notify(notifyMessage, "warning");
    }

    const skillInputMessage = formatSkillAskPrompt(
      skillName,
      agentName ?? undefined,
    );
    const suggestion = suggestSessionPattern("skill", skillName);
    const skillInputPromptDetails = {
      source: "skill_input" as const,
      agentName,
      message: skillInputMessage,
      skillName,
      sessionLabel: suggestion.label,
    };
    const skillInputCanConfirm = session.canPrompt(ctx, skillInputPromptDetails);
    let skillInputAutoApproved = false;
    const skillInputGate = await applyPermissionGate({
      state: check.state,
      canConfirm: skillInputCanConfirm,
      promptForApproval: async () => {
        const decision = await session.prompt(ctx, {
          requestId: session.createPermissionRequestId("skill-input"),
          ...skillInputPromptDetails,
        });
        skillInputAutoApproved = decision.autoApproved === true;
        return decision;
      },
      // eslint-disable-next-line @typescript-eslint/unbound-method -- logger.review is a plain function closure; no this-binding issue
      writeLog: session.logger.review,
      logContext: {
        source: "skill_input",
        skillName,
        agentName,
        message: skillInputMessage,
      },
      messages: {
        denyReason: skillInputMessage,
        unavailableReason:
          "Skill requires approval, but no interactive UI is available.",
        userDeniedReason: () => "User denied skill.",
      },
    });

    const skillInputApprovalKind =
      skillInputGate.action === "allow"
        ? skillInputGate.approval?.kind ?? null
        : null;

    if (skillInputGate.action === "allow") {
      if (skillInputApprovalKind === "session") {
        session.approveSessionRule(suggestion.surface, suggestion.pattern);
      } else if (skillInputApprovalKind === "workspace" || skillInputApprovalKind === "global") {
        session.persistPermissionRule(
          skillInputApprovalKind,
          suggestion.surface,
          suggestion.pattern,
        );
      }
    }

    emitDecisionEvent(this.events, {
      surface: "skill",
      value: skillName,
      result: skillInputGate.action === "allow" ? "allow" : "deny",
      /* eslint-disable @typescript-eslint/no-unnecessary-condition -- defensive fallback; TypeScript narrows check.state before the ternary's else branch */
      resolution:
        check.state === "allow"
          ? "policy_allow"
          : check.state === "deny"
            ? "policy_deny"
            : skillInputGate.action === "allow"
              ? skillInputAutoApproved
                ? "auto_approved"
                : skillInputApprovalKind === "session"
                  ? "user_approved_for_session"
                  : skillInputApprovalKind === "workspace"
                    ? "user_approved_for_workspace"
                    : skillInputApprovalKind === "global"
                      ? "user_approved_globally"
                      : "user_approved"
              : skillInputCanConfirm
                ? "user_denied"
                : "confirmation_unavailable",
      /* eslint-enable @typescript-eslint/no-unnecessary-condition */
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- ?? null normalises undefined to null for the log record
      origin: check.origin ?? null,
      agentName: agentName ?? null,
      matchedPattern: check.matchedPattern ?? null,
    });

    if (skillInputGate.action === "block") {
      return { action: "handled" };
    }

    return { action: "continue" };
  }
}

// ── Pure helpers (re-exported from original modules) ──────────────────────

/**
 * Extract the tool input from an event, checking both `input` and `arguments`
 * fields (different Pi SDK versions use different names).
 */
export function getEventInput(event: unknown): unknown {
  const record = toRecord(event);

  if (record.input !== undefined) {
    return record.input;
  }

  if (record.arguments !== undefined) {
    return record.arguments;
  }

  return {};
}

/**
 * Parse a `/skill:<name>` prefix from user input.
 * Returns the skill name, or null if the text is not a skill invocation.
 */
export function extractSkillNameFromInput(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("/skill:")) {
    return null;
  }

  const afterPrefix = trimmed.slice("/skill:".length);
  if (!afterPrefix) {
    return null;
  }

  const firstWhitespace = afterPrefix.search(/\s/);
  const skillName = (
    firstWhitespace === -1 ? afterPrefix : afterPrefix.slice(0, firstWhitespace)
  ).trim();
  return skillName || null;
}
