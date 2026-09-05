import type { PermissionDecisionResolution } from "#src/permission-events";
import type { PermissionCheckResult } from "#src/types";

/**
 * Derive the human-readable value for a decision event from a check result.
 * Bash → extracted command; MCP → qualified target;
 * path-bearing tools → file path; others → tool name.
 */
export function deriveDecisionValue(
  toolName: string,
  check: Pick<PermissionCheckResult, "command" | "target">,
  path?: string,
): string {
  if (toolName === "bash") return check.command ?? toolName;
  if (toolName === "mcp") return check.target ?? toolName;
  if (path) return path;
  return toolName;
}

/**
 * Map the gate outcome back to a PermissionDecisionResolution.
 *
 * @param state     - The permission state passed to the gate.
 * @param action    - The gate's resulting action ("allow" | "block").
 * @param hasSession - True when the gate result carries a sessionApproval
 *                    (indicates the user chose "for this session").
 * @param canConfirm - Whether an interactive prompt was available.
 */
export function deriveResolution(
  state: "allow" | "deny" | "ask",
  action: "allow" | "block",
  approvalKind: "session" | "workspace" | "global" | null,
  canConfirm: boolean,
  autoApproved = false,
): PermissionDecisionResolution {
  if (state === "allow") return "policy_allow";
  if (state === "deny") return "policy_deny";
  // state === "ask"
  if (action === "allow") {
    if (autoApproved) return "auto_approved";
    if (approvalKind === "session") return "user_approved_for_session";
    if (approvalKind === "workspace") return "user_approved_for_workspace";
    if (approvalKind === "global") return "user_approved_globally";
    return "user_approved";
  }
  return canConfirm ? "user_denied" : "confirmation_unavailable";
}
