import {
  getPathBearingToolPath,
  getPathPolicyCandidates,
  isWorkspaceLocalFileOperation,
  sensitiveEnvPathForPolicy,
} from "#src/path-utils";
import type { Rule } from "#src/rule";
import { deriveApprovalPattern } from "#src/session-rules";
import type { PermissionCheckResult } from "#src/types";
import type { GateDescriptor, GateResult } from "./descriptor";
import type { ToolCallContext } from "./types";

/** Function type for checkPermission used by the descriptor factory. */
type CheckPermissionFn = (
  surface: string,
  input: unknown,
  agentName?: string,
  sessionRules?: Rule[],
) => PermissionCheckResult;

function permissionRank(state: PermissionCheckResult["state"]): number {
  return state === "deny" ? 2 : state === "ask" ? 1 : 0;
}

export function isDotenvPolicyPattern(pattern: string | undefined): boolean {
  switch (pattern?.toLowerCase()) {
    case "*.env":
    case "*.env.*":
      return true;
    default:
      return false;
  }
}

function isDotenvRestriction(check: PermissionCheckResult): boolean {
  return check.state === "deny" && isDotenvPolicyPattern(check.matchedPattern);
}

function evaluatePathPolicyCandidates(
  filePath: string,
  cwd: string,
  agentName: string | undefined,
  sessionRules: Rule[],
  checkPermission: CheckPermissionFn,
): { check: PermissionCheckResult; hasOnlyDotenvRestrictions: boolean } {
  const checks = getPathPolicyCandidates(filePath, cwd).map((path) =>
    checkPermission("path", { path }, agentName, sessionRules),
  );
  const check = checks.reduce((strictest, candidate) => {
    const rank = permissionRank(candidate.state);
    const strictestRank = permissionRank(strictest.state);
    return rank > strictestRank
      || (rank === strictestRank && strictest.matchedPattern === undefined && candidate.matchedPattern !== undefined)
      ? candidate
      : strictest;
  });
  const hasDotenvRestriction = checks.some(isDotenvRestriction);
  const hasOtherRestriction = checks.some((candidate) =>
    candidate.state !== "allow" && !isDotenvRestriction(candidate),
  );
  return {
    check,
    hasOnlyDotenvRestrictions: hasDotenvRestriction && !hasOtherRestriction,
  };
}

function buildPathGateDescriptor(
  tcc: ToolCallContext,
  filePath: string,
  check: PermissionCheckResult,
): GateDescriptor {
  const pattern = deriveApprovalPattern(filePath);

  const descriptor: GateDescriptor = {
    surface: "path",
    input: { path: filePath },
    denialContext: {
      kind: "path",
      toolName: tcc.toolName,
      pathValue: filePath,
      agentName: tcc.agentName ?? undefined,
    },
    sessionApproval: {
      surface: "path",
      pattern,
    },
    promptDetails: {
      source: "tool_call",
      agentName: tcc.agentName,
      message: formatPathAskPrompt(
        tcc.toolName,
        filePath,
        tcc.agentName ?? undefined,
      ),
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      path: filePath,
    },
    logContext: {
      source: "tool_call",
      toolCallId: tcc.toolCallId,
      toolName: tcc.toolName,
      agentName: tcc.agentName,
      path: filePath,
    },
    decision: {
      surface: "path",
      value: filePath,
    },
    preCheck: check,
  };

  return descriptor;
}

/**
 * Build a pure descriptor for the cross-cutting path permission gate (tools).
 *
 * Returns `null` when the gate does not apply (tool is not path-bearing,
 * no extractable path, the `path` surface evaluates to `allow`, or no
 * explicit `path` rule matched — i.e. only the universal default fired).
 * Returns a `GateDescriptor` when the path matches a `deny` or `ask` rule.
 */
export function describePathGate(
  tcc: ToolCallContext,
  checkPermission: CheckPermissionFn,
  getSessionRuleset: () => Rule[],
): GateResult {
  const filePath = getPathBearingToolPath(tcc.toolName, tcc.input);
  if (!filePath) return null;

  const sessionRules = getSessionRuleset();
  const cwd = tcc.cwd ?? process.cwd();
  const sensitiveEnvPolicyPath = sensitiveEnvPathForPolicy(filePath, cwd);
  const { check, hasOnlyDotenvRestrictions } = evaluatePathPolicyCandidates(
    filePath,
    cwd,
    tcc.agentName ?? undefined,
    sessionRules,
    checkPermission,
  );
  if (check.state === "allow") return null;

  // Allow workspace-local dotenv reads while keeping writes and other paths protected.
  if (
    tcc.toolName === "read"
    && tcc.cwd
    && sensitiveEnvPolicyPath !== null
    && hasOnlyDotenvRestrictions
    && isWorkspaceLocalFileOperation(tcc.toolName, tcc.input, tcc.cwd, {
      allowWorkspaceEnvRead: true,
    })
  ) {
    return null;
  }

  // No explicit path rule matched — only the universal default fired.
  // Skip the gate to preserve backward compatibility: configs without a
  // "path" key should not trigger path-level prompts (#58).
  if (check.matchedPattern === undefined) return null;

  return buildPathGateDescriptor(tcc, filePath, check);
}

export function formatPathAskPrompt(
  toolName: string,
  pathValue: string,
  agentName?: string,
): string {
  const subject = agentName ? `Agent '${agentName}'` : "Current agent";
  return `${subject} requested tool '${toolName}' for path '${pathValue}'. Allow this path access?`;
}
