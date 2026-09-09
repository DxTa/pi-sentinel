import { getNonEmptyString, toRecord } from "#src/common";
import type { Rule } from "#src/rule";
import { deriveApprovalPattern } from "#src/session-rules";
import type { PermissionCheckResult } from "#src/types";
import { extractExternalPathsFromBashCommand } from "./bash-path-extractor";
import type { GateResult } from "./descriptor";
import { formatBashExternalDirectoryAskPrompt } from "./external-directory-messages";
import type { ToolCallContext } from "./types";

const READ_ONLY_EXTERNAL_BASH_COMMANDS: ReadonlySet<string> = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "grep",
  "rg",
  "ag",
  "wc",
  "sort",
  "uniq",
  "diff",
  "ls",
  "find",
  "stat",
  "du",
  "df",
]);

const COMPLEX_SHELL_PATTERN = /&&|\|\||[;`]/;
const OUTPUT_REDIRECTION_PATTERN = />>?|&>|>\|/;

/** Function type for checkPermission used by the descriptor factory. */
type CheckPermissionFn = (
  surface: string,
  input: unknown,
  agentName?: string,
  sessionRules?: Rule[],
) => PermissionCheckResult;

function shouldForcePromptBashExternalDirectoryInYolo(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed) {
    return true;
  }

  if (
    COMPLEX_SHELL_PATTERN.test(trimmed)
    || trimmed.includes("\n")
    || trimmed.includes("$(")
    || trimmed.includes("|")
    || OUTPUT_REDIRECTION_PATTERN.test(trimmed)
  ) {
    return true;
  }

  const commandName = trimmed.split(/\s+/, 1)[0] ?? "";
  return !READ_ONLY_EXTERNAL_BASH_COMMANDS.has(commandName);
}

/**
 * Build a pure descriptor for the bash external-directory permission gate.
 *
 * Extracts paths from a bash command and checks whether any reference
 * directories outside the working directory. Returns `null` when the gate
 * does not apply (tool is not bash, no CWD, or no external paths found).
 * Returns a `GateBypass` when all paths are already allowed.
 * Returns a `GateDescriptor` with multi-pattern sessionApproval for uncovered paths.
 */
export async function describeBashExternalDirectoryGate(
  tcc: ToolCallContext,
  checkPermission: CheckPermissionFn,
  getSessionRuleset: () => Rule[],
): Promise<GateResult> {
  if (tcc.toolName !== "bash" || !tcc.cwd) return null;

  const command = getNonEmptyString(toRecord(tcc.input).command);
  if (!command) return null;

  const externalPaths = await extractExternalPathsFromBashCommand(
    command,
    tcc.cwd,
  );
  if (externalPaths.length === 0) return null;

  const bashSessionRules = getSessionRuleset();
  const externalPathChecks = externalPaths.map((path) => ({
    path,
    check: checkPermission(
      "external_directory",
      { path },
      tcc.agentName ?? undefined,
      bashSessionRules,
    ),
  }));
  const uncoveredPathChecks = externalPathChecks.filter(
    ({ check }) => check.state !== "allow",
  );

  if (uncoveredPathChecks.length === 0) {
    return {
      action: "allow",
      log: {
        event: "permission_request.session_approved",
        details: {
          source: "tool_call",
          toolCallId: tcc.toolCallId,
          toolName: tcc.toolName,
          agentName: tcc.agentName,
          command,
          externalPaths,
          resolution: "session_approved",
        },
      },
    };
  }

  const uncoveredPaths = uncoveredPathChecks.map(({ path }) => path);
  const preCheck =
    uncoveredPathChecks.find(({ check }) => check.state === "deny")?.check
    ?? uncoveredPathChecks[0]!.check;

  const bashExtMessage = formatBashExternalDirectoryAskPrompt(
    command,
    uncoveredPaths,
    tcc.cwd,
    tcc.agentName ?? undefined,
  );

  const patterns = uncoveredPaths.map((path) => deriveApprovalPattern(path));
  const forcePromptInYolo = shouldForcePromptBashExternalDirectoryInYolo(command);

  return {
    surface: "external_directory",
    input: {},
    denialContext: {
      kind: "bash_external_directory",
      command,
      externalPaths: uncoveredPaths,
      cwd: tcc.cwd,
      agentName: tcc.agentName ?? undefined,
    },
    sessionApproval: {
      surface: "external_directory",
      patterns,
    },
    promptDetails: {
      source: "tool_call",
      agentName: tcc.agentName,
      message: bashExtMessage,
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      command,
      ...(forcePromptInYolo ? { forcePromptInYolo: true } : {}),
    },
    logContext: {
      source: "tool_call",
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      agentName: tcc.agentName,
      command,
      externalPaths: uncoveredPaths,
      message: bashExtMessage,
    },
    decision: {
      surface: "external_directory",
      value: command,
    },
    preCheck,
  };
}
