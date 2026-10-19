import { homedir } from "node:os";

import { toRecord } from "#src/common";
import { relative, resolve } from "node:path";

import {
  getPathBearingToolPath,
  hasProtectedEnvSelector,
  isWorkspaceLocalFileOperation,
  normalizePathForComparison,
  PATH_BEARING_TOOLS,
  READ_ONLY_PATH_BEARING_TOOLS,
} from "#src/path-utils";
import { isSensitivePath } from "../../yolo-auto-sensitive-paths";
import { bashInnerCommands } from "#src/bash-segments";
import { matchesGitPushCommand } from "#src/yolo-mode";
import { suggestSessionPattern } from "#src/pattern-suggest";
import { formatAskPrompt } from "#src/permission-prompts";
import { getEditReplacementText, getPermissionLogContext } from "#src/tool-input-preview";
import { buildYoloAutoText } from "../../yolo-auto-client";
import type { PermissionCheckResult } from "#src/types";
import type { GateDescriptor } from "./descriptor";
import { deriveDecisionValue } from "./helpers";
import type { ToolCallContext } from "./types";

/**
 * Derive the value used for session-approval pattern suggestions.
 *
 * Bash → command string; MCP → qualified target;
 * path-bearing tools → file path; others → catch-all wildcard.
 */
function deriveSuggestionValue(
  tcc: ToolCallContext,
  check: PermissionCheckResult,
): string {
  if (tcc.toolName === "bash") {
    const command = check.command ?? "";
    const inner = bashInnerCommands(command);
    return inner?.commands.length === 1 ? inner.commands[0]! : command;
  }
  if (tcc.toolName === "mcp") return check.target ?? "mcp";
  return getPathBearingToolPath(tcc.toolName, tcc.input) ?? "*";
}

/**
 * Bash rules match the inner commands, so a session approval stores one pattern
 * per distinct inner command. Code that cannot be read statically and elevated
 * commands store nothing, so approving them never covers a later command.
 */
function sessionApprovalFor(
  tcc: ToolCallContext,
  check: PermissionCheckResult,
  suggestion: { surface: string; pattern: string },
): { surface: string; pattern: string } | { surface: string; patterns: string[] } {
  if (tcc.toolName !== "bash") return { surface: suggestion.surface, pattern: suggestion.pattern };
  const inner = bashInnerCommands(check.command ?? "");
  if (!inner || inner.opaque || inner.elevated) return { surface: "bash", patterns: [] };
  const patterns = [...new Set(inner.commands.map((command) => suggestSessionPattern("bash", command).pattern))];
  return patterns.length === 1 ? { surface: "bash", pattern: patterns[0]! } : { surface: "bash", patterns };
}

/**
 * Build a pure descriptor for the normal tool permission gate.
 *
 * Takes a pre-computed PermissionCheckResult (from checkPermission) and
 * returns a GateDescriptor that the runner can execute. No side effects.
 */
export function describeToolGate(
  tcc: ToolCallContext,
  check: PermissionCheckResult,
): GateDescriptor {
  const permissionLogContext = getPermissionLogContext(
    check,
    tcc.input,
    PATH_BEARING_TOOLS,
  );

  // Compute session approval suggestion for the "for this session" option.
  const suggestion = suggestSessionPattern(
    tcc.toolName,
    deriveSuggestionValue(tcc, check),
  );

  const freshApproval =
    tcc.toolName === "bash" && matchesGitPushCommand(check.command ?? "");
  const sessionApproval = freshApproval
    ? undefined
    : sessionApprovalFor(tcc, check, suggestion);
  const sessionLabel = !sessionApproval
    ? undefined
    : "patterns" in sessionApproval
      ? sessionApproval.patterns.length === 0
        ? "Yes, allow this once (code that cannot be matched is not remembered)"
        : 'Yes, allow bash ' + sessionApproval.patterns.map((p) => JSON.stringify(p)).join(', ') + ' for this session'
      : suggestion.label;

  const askMessage = formatAskPrompt(
    check,
    tcc.agentName ?? undefined,
    tcc.input,
  );
  const toolPath = getPathBearingToolPath(tcc.toolName, tcc.input);
  const inputRecord = toRecord(tcc.input);
  const yoloAutoCommand = tcc.yoloAutoCommand;
  const yoloAutoOperation =
    tcc.toolName === "read"
      ? "read"
      : READ_ONLY_PATH_BEARING_TOOLS.has(tcc.toolName)
        ? "list"
        : tcc.toolName === "write" || tcc.toolName === "edit"
          ? tcc.toolName
          : tcc.toolName === "bash" ? "exec" : undefined;
  const yoloAutoWorkspaceLocal = yoloAutoOperation === "exec"
    ? tcc.yoloAutoWorkspaceLocal === true
      && Boolean(yoloAutoCommand?.trim())
      && Boolean(tcc.cwd)
    : yoloAutoOperation !== undefined
      && tcc.cwd !== undefined
      && isWorkspaceLocalFileOperation(tcc.toolName, tcc.input, tcc.cwd, {
        allowWorkspaceEnvRead: true,
      });
  const yoloAutoWorkspaceRelativePath =
    yoloAutoWorkspaceLocal && toolPath && tcc.cwd
      ? relative(tcc.cwd, resolve(tcc.cwd, toolPath)).replaceAll("\\", "/")
      : undefined;
  const yoloAutoContent = yoloAutoOperation === "write"
    ? typeof inputRecord.content === "string" ? inputRecord.content : undefined
    : yoloAutoOperation === "edit" ? getEditReplacementText(inputRecord) : undefined;
  const yoloAutoTextTruncated = yoloAutoOperation === "exec"
    ? false
    : (yoloAutoContent?.length ?? 0) > 800;
  const yoloAutoText = yoloAutoWorkspaceLocal && yoloAutoOperation !== undefined
    ? yoloAutoOperation === "exec" && yoloAutoCommand !== undefined
      ? buildYoloAutoText({ toolName: tcc.toolName, operation: yoloAutoOperation, command: yoloAutoCommand! })
      : yoloAutoContent !== undefined
        ? buildYoloAutoText({
            toolName: tcc.toolName,
            operation: yoloAutoOperation,
            ...(yoloAutoWorkspaceRelativePath
              ? { workspaceRelativePath: yoloAutoWorkspaceRelativePath }
              : {}),
            content: yoloAutoContent,
          })
        : undefined
    : undefined;
  const yoloAutoInner = yoloAutoOperation === "exec" ? bashInnerCommands(yoloAutoCommand ?? "") : null;
  const forcePromptInYolo =
    freshApproval || hasProtectedEnvSelector(tcc.toolName, tcc.input);
  const yoloAutoHardRuleTarget = yoloAutoWorkspaceLocal && tcc.cwd
    ? toolPath
      ? normalizePathForComparison(toolPath, tcc.cwd)
      : yoloAutoOperation === "list"
        ? normalizePathForComparison(tcc.cwd, tcc.cwd)
        : ""
    : "";
  const yoloAutoHardRuleHit = yoloAutoOperation === "exec"
    ? tcc.yoloAutoHardRuleHit ?? true
    : !yoloAutoHardRuleTarget
      || isSensitivePath(yoloAutoHardRuleTarget, homedir());

  return {
    surface: tcc.toolName,
    input: tcc.input,
    denialContext: {
      kind: "tool",
      check,
      agentName: tcc.agentName ?? undefined,
      input: tcc.input,
    },
    ...(sessionApproval ? { sessionApproval } : {}),
    ...(freshApproval ? { freshApproval: true } : {}),
    promptDetails: {
      source: "tool_call",
      agentName: tcc.agentName,
      message: askMessage,
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      ...(sessionLabel ? { sessionLabel } : {}),
      ...(freshApproval ? { allowSession: false } : {}),
      ...permissionLogContext,
      ...(yoloAutoOperation
        ? {
            yoloAutoEligible: check.state === "ask"
              && yoloAutoWorkspaceLocal
              && (yoloAutoOperation !== "exec"
                // Elevated commands always prompt.
                || (yoloAutoInner?.elevated !== true
                  && (tcc.sandboxed === true
                    // Host Bash reaches the model only without command substitution.
                    || yoloAutoInner !== null))),
            yoloAutoWorkspaceLocal,
            yoloAutoHardRuleHit,
            ...(yoloAutoWorkspaceRelativePath
              ? { yoloAutoWorkspaceRelativePath }
              : {}),
            yoloAutoOperation,
            ...(yoloAutoOperation === "exec"
              ? {
                  yoloAutoSandboxed: tcc.sandboxed === true,
                  ...(tcc.yoloAutoUnits ? { yoloAutoUnits: [...tcc.yoloAutoUnits], yoloAutoOpaque: tcc.yoloAutoOpaque === true } : {}),
                }
              : {}),
            ...(yoloAutoText !== undefined ? { yoloAutoText, yoloAutoTextTruncated } : {}),
            ...(forcePromptInYolo ? { forcePromptInYolo: true } : {}),
          }
        : {}),
    },
    logContext: {
      source: "tool_call",
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      message: askMessage,
      ...permissionLogContext,
    },
    decision: {
      surface: tcc.toolName,
      value: deriveDecisionValue(
        tcc.toolName,
        check,
        getPathBearingToolPath(tcc.toolName, tcc.input) ?? undefined,
      ),
    },
  };
}
