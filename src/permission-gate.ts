import type { PermissionPromptDecision } from "./permission-dialog";

/** Result of applying the permission gate. */
export type PermissionGateResult =
  | {
      action: "allow";
      approval?: { kind: "session" | "workspace" | "global" };
    }
  | { action: "block"; reason: string };

/** Everything the gate needs — no direct dependency on ExtensionContext. */
export interface PermissionGateParams {
  /** The resolved permission state from checkPermission(). */
  state: "allow" | "deny" | "ask";

  /** Whether the current context supports interactive prompts. */
  canConfirm: boolean;

  /** Prompt the user for approval. Only called when state === "ask" and canConfirm is true. */
  promptForApproval: () => Promise<PermissionPromptDecision>;

  /**
   * Session approval suggestion to record when the user selects
   * "for this session". When present and the decision is `approved_for_session`,
   * the result carries the suggestion back to the caller for recording.
   */
  sessionApproval?: { surface: string; pattern: string };

  /** Write a review-log entry. Called for deny and ask-but-unavailable paths. */
  writeLog: (event: string, extra: Record<string, unknown>) => void;

  /** Log context fields shared across all log calls for this gate. */
  logContext: Record<string, unknown>;

  /** Message strings/factories for each outcome. */
  messages: {
    denyReason: string;
    unavailableReason: string;
    userDeniedReason: (decision: PermissionPromptDecision) => string;
  };
}

/**
 * Apply the deny/ask/allow permission gate.
 *
 * This is a pure decision function: all IO is injected via callbacks.
 */
export async function applyPermissionGate(
  params: PermissionGateParams,
): Promise<PermissionGateResult> {
  const {
    state,
    canConfirm,
    promptForApproval,
    writeLog,
    logContext,
    messages,
  } = params;

  if (state === "deny") {
    writeLog("permission_request.blocked", {
      ...logContext,
      resolution: "policy_denied",
    });
    return { action: "block", reason: messages.denyReason };
  }

  if (state === "ask") {
    if (!canConfirm) {
      writeLog("permission_request.blocked", {
        ...logContext,
        resolution: "confirmation_unavailable",
      });
      return { action: "block", reason: messages.unavailableReason };
    }

    const decision = await promptForApproval();
    if (!decision.approved) {
      return { action: "block", reason: messages.userDeniedReason(decision) };
    }
    if (decision.state === "approved_for_session") {
      return { action: "allow", approval: { kind: "session" } };
    }
    if (decision.state === "approved_for_workspace") {
      return { action: "allow", approval: { kind: "workspace" } };
    }
    if (decision.state === "approved_globally") {
      return { action: "allow", approval: { kind: "global" } };
    }
  }

  return { action: "allow" };
}
