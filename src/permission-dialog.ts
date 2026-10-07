export type PermissionDecisionState =
  | "approved"
  | "approved_for_session"
  | "approved_for_workspace"
  | "approved_globally"
  | "denied"
  | "denied_with_reason";

export type PermissionPromptDecision = {
  approved: boolean;
  state: PermissionDecisionState;
  denialReason?: string;
  /**
   * True when the decision was made automatically by yolo mode rather than
   * by an interactive user prompt. Used by handlers to emit "auto_approved"
   * rather than "user_approved" in the permissions:decision broadcast.
   */
  autoApproved?: true;
  /**
   * True only when a person chose this answer in a permission dialog. Failures,
   * timeouts, dismissed dialogs, and auto-approvals leave it unset so they never
   * become learning labels.
   */
  humanDecided?: true;
};

export interface PermissionDecisionUi {
  select(title: string, options: string[]): Promise<string | undefined>;
  input(title: string, placeholder?: string): Promise<string | undefined>;
}

const APPROVE_OPTION = "Yes";
const APPROVE_FOR_SESSION_OPTION = "Yes, for this session";
const APPROVE_FOR_WORKSPACE_OPTION = "Yes, for this workspace";
const APPROVE_GLOBALLY_OPTION = "Yes, globally";
const DENY_OPTION = "No";
const DENY_WITH_REASON_OPTION = "No, provide reason";
const PERMISSION_DECISION_OPTIONS = [
  APPROVE_OPTION,
  APPROVE_FOR_SESSION_OPTION,
  APPROVE_FOR_WORKSPACE_OPTION,
  APPROVE_GLOBALLY_OPTION,
  DENY_OPTION,
  DENY_WITH_REASON_OPTION,
] as const;

export function normalizePermissionDenialReason(
  value: unknown,
): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function createDeniedPermissionDecision(
  denialReason?: string,
): PermissionPromptDecision {
  const normalizedReason = normalizePermissionDenialReason(denialReason);
  return normalizedReason
    ? {
        approved: false,
        state: "denied_with_reason",
        denialReason: normalizedReason,
      }
    : {
        approved: false,
        state: "denied",
      };
}

const humanDecision = (decision: PermissionPromptDecision): PermissionPromptDecision => ({
  ...decision,
  humanDecided: true,
});

export function isPermissionDecisionState(
  value: unknown,
): value is PermissionDecisionState {
  return (
    value === "approved" ||
    value === "approved_for_session" ||
    value === "approved_for_workspace" ||
    value === "approved_globally" ||
    value === "denied" ||
    value === "denied_with_reason"
  );
}

export interface RequestPermissionOptions {
  /** Override the "for this session" option label (e.g. to show the suggested pattern). */
  sessionLabel?: string;
  /** Override the workspace-persistence label. */
  workspaceLabel?: string;
  /** Override the global-persistence label. */
  globalLabel?: string;
  /** Whether workspace persistence is available for this prompt. */
  allowWorkspace?: boolean;
  /** Whether global persistence is available for this prompt. */
  allowGlobal?: boolean;
}

export async function requestPermissionDecisionFromUi(
  ui: PermissionDecisionUi,
  title: string,
  message: string,
  options?: RequestPermissionOptions,
): Promise<PermissionPromptDecision> {
  const sessionOption = options?.sessionLabel ?? APPROVE_FOR_SESSION_OPTION;
  const workspaceOption =
    options?.workspaceLabel ?? APPROVE_FOR_WORKSPACE_OPTION;
  const globalOption = options?.globalLabel ?? APPROVE_GLOBALLY_OPTION;
  const allowWorkspace = options?.allowWorkspace !== false;
  const allowGlobal = options?.allowGlobal !== false;
  const decisionOptions = [
    APPROVE_OPTION,
    sessionOption,
    ...(allowWorkspace ? [workspaceOption] : []),
    ...(allowGlobal ? [globalOption] : []),
    DENY_OPTION,
    DENY_WITH_REASON_OPTION,
  ] as const;

  const selected = await ui.select(`${title}\n${message}`, [
    ...decisionOptions,
  ]);

  if (selected === APPROVE_OPTION) {
    return humanDecision({ approved: true, state: "approved" });
  }

  if (selected === sessionOption) {
    return humanDecision({ approved: true, state: "approved_for_session" });
  }

  if (allowWorkspace && selected === workspaceOption) {
    return humanDecision({ approved: true, state: "approved_for_workspace" });
  }

  if (allowGlobal && selected === globalOption) {
    return humanDecision({ approved: true, state: "approved_globally" });
  }

  if (selected === DENY_WITH_REASON_OPTION) {
    const denialReason = normalizePermissionDenialReason(
      await ui.input(
        `${title}\nShare why this request was denied (optional).`,
        "Reason shown back to the agent",
      ),
    );

    return humanDecision(createDeniedPermissionDecision(denialReason));
  }

  // A dismissed dialog (undefined) is not a deliberate answer.
  return selected === DENY_OPTION
    ? humanDecision(createDeniedPermissionDecision())
    : createDeniedPermissionDecision();
}
