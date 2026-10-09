import { isReadOnlyBashCommand } from "#src/bash-command-safety";
import { getNonEmptyString, toRecord } from "#src/common";
import { isPathWithinDirectory, normalizePathForComparison } from "#src/path-utils";
import type { Rule } from "#src/rule";
import { deriveApprovalPattern } from "#src/session-rules";
import type { PermissionCheckResult } from "#src/types";
import { extractExternalPathsFromBashCommand } from "./bash-path-extractor";
import type { GateResult } from "./descriptor";
import { formatBashExternalDirectoryAskPrompt } from "./external-directory-messages";
import type { ToolCallContext } from "./types";

const COMMAND_WRAPPERS = new Set(["sudo", "command", "env", "exec"]);
const HARD_BLOCKED_MUTATING_COMMANDS = new Set([
  "rm", "rmdir", "unlink", "mv", "cp", "install", "mkdir",
  "touch", "ln", "chmod", "chown", "chgrp", "truncate", "tee", "dd",
]);
const SAFE_EXTERNAL_MUTATION_ROOTS = ["/tmp", "/private/tmp"] as const;

function hasPotentiallyMutatingCommand(command: string): boolean {
  const segments = command.split(String.fromCharCode(38, 59, 124, 36, 40));
  for (const segment of segments) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    while (COMMAND_WRAPPERS.has(tokens[0] ?? "")) tokens.shift();
    const commandName = tokens[0]?.split("/").pop() ?? "";
    if (commandName === "find") {
      if (tokens.includes("-delete")) return true;
    }
    if (HARD_BLOCKED_MUTATING_COMMANDS.has(commandName)) return true;
  }
  return false;
}

function isSafeMutationPath(pathValue: string, cwd: string): boolean {
  const normalizedPath = normalizePathForComparison(pathValue, cwd);
  const normalizedCwd = normalizePathForComparison(cwd, cwd);
  if (normalizedPath.length === 0 || normalizedCwd.length === 0) return false;
  if (isPathWithinDirectory(normalizedPath, normalizedCwd)) return true;
  return SAFE_EXTERNAL_MUTATION_ROOTS.some((root) =>
    isPathWithinDirectory(normalizedPath, normalizePathForComparison(root, cwd)),
  );
}

export function getHardBlockedBashMutationPaths(
  command: string,
  cwd: string,
  externalPaths: readonly string[],
): string[] {
  if (hasPotentiallyMutatingCommand(command) === false) return [];
  const executablePaths = new Set<string>();
  for (const segment of command.split(String.fromCharCode(38, 59, 124, 36, 40))) {
    const tokens = segment.trim().split(String.fromCharCode(32)).filter(Boolean);
    while (COMMAND_WRAPPERS.has(tokens[0] ?? "")) tokens.shift();
    const executable = tokens[0] ?? "";
    if (executable.includes(String.fromCharCode(47))) {
      executablePaths.add(normalizePathForComparison(executable, cwd));
    }
  }
  return externalPaths.filter((pathValue) =>
    executablePaths.has(pathValue) === false
    && isSafeMutationPath(pathValue, cwd) === false,
  );
}

/** Function type for checkPermission used by the descriptor factory. */
type CheckPermissionFn = (
  surface: string,
  input: unknown,
  agentName?: string,
  sessionRules?: Rule[],
) => PermissionCheckResult;

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

  const unsafeMutationPaths = getHardBlockedBashMutationPaths(
    command,
    tcc.cwd,
    externalPaths,
  );
  if (unsafeMutationPaths.length > 0 && tcc.mode !== "yolo") {
    if (hasPotentiallyMutatingCommand(command)) {
      const hardBlockMessage =
        "Blocked mutating Bash command outside workspace or temporary roots: "
        + unsafeMutationPaths.join(", ");
      return {
        surface: "external_directory",
        input: {},
        denialContext: {
          kind: "bash_external_directory",
          command,
          externalPaths: unsafeMutationPaths,
          cwd: tcc.cwd,
          agentName: tcc.agentName ?? undefined,
        },
        promptDetails: {
          source: "tool_call",
          agentName: tcc.agentName,
          message: hardBlockMessage,
          toolCallId: tcc.toolCallId,
          toolName: tcc.toolName,
          command,
        },
        logContext: {
          source: "tool_call",
          toolCallId: tcc.toolCallId,
          toolName: tcc.toolName,
          agentName: tcc.agentName,
          command,
          externalPaths: unsafeMutationPaths,
          hardBlock: true,
        },
        decision: {
          surface: "external_directory",
          value: command,
        },
        preResolved: { state: "deny" },
      };
    }
  }
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
  const forcePromptInYolo = tcc.mode !== "yolo" && !isReadOnlyBashCommand(command);

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
