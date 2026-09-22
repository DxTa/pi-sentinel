import { relative, resolve } from "node:path";

import {
  getPathBearingToolPath,
  hasProtectedEnvSelector,
  isWorkspaceLocalFileOperation,
  PATH_BEARING_TOOLS,
  READ_ONLY_PATH_BEARING_TOOLS,
} from "#src/path-utils";
import { suggestSessionPattern } from "#src/pattern-suggest";
import { formatAskPrompt } from "#src/permission-prompts";
import { getPermissionLogContext } from "#src/tool-input-preview";
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
  if (tcc.toolName === "bash") return check.command ?? "";
  if (tcc.toolName === "mcp") return check.target ?? "mcp";
  return getPathBearingToolPath(tcc.toolName, tcc.input) ?? "*";
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

  const askMessage = formatAskPrompt(
    check,
    tcc.agentName ?? undefined,
    tcc.input,
  );
  const toolPath = getPathBearingToolPath(tcc.toolName, tcc.input);
  const yoloAutoOperation =
    tcc.toolName === "read"
      ? "read"
      : READ_ONLY_PATH_BEARING_TOOLS.has(tcc.toolName)
        ? "list"
        : undefined;
  const yoloAutoWorkspaceLocal =
    yoloAutoOperation !== undefined
    && tcc.cwd !== undefined
    && isWorkspaceLocalFileOperation(tcc.toolName, tcc.input, tcc.cwd, {
      allowWorkspaceEnvRead: true,
    });
  const forcePromptInYolo = hasProtectedEnvSelector(tcc.toolName, tcc.input);
  const yoloAutoWorkspaceRelativePath =
    yoloAutoWorkspaceLocal && toolPath && tcc.cwd
      ? relative(tcc.cwd, resolve(tcc.cwd, toolPath)).replaceAll("\\", "/")
      : undefined;

  return {
    surface: tcc.toolName,
    input: tcc.input,
    denialContext: {
      kind: "tool",
      check,
      agentName: tcc.agentName ?? undefined,
      input: tcc.input,
    },
    sessionApproval: {
      surface: suggestion.surface,
      pattern: suggestion.pattern,
    },
    promptDetails: {
      source: "tool_call",
      agentName: tcc.agentName,
      message: askMessage,
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      sessionLabel: suggestion.label,
      ...permissionLogContext,
      ...(yoloAutoOperation
        ? {
            yoloAutoEligible: check.state === "ask" && yoloAutoWorkspaceLocal,
            yoloAutoWorkspaceLocal,
            ...(yoloAutoWorkspaceRelativePath
              ? { yoloAutoWorkspaceRelativePath }
              : {}),
            yoloAutoOperation,
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
