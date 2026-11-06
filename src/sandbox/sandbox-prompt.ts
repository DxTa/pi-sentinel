/**
 * Sandbox prompt — Ask/allow/deny UI for SRT policy changes.
 *
 * Uses the same UX pattern as the upstream permission system:
 * When a command needs a sandbox policy change (network access, new path),
 * prompt the user with choices: Allow once / Allow for session / Allow always / Deny.
 */

import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { PromptWaitTracker } from "../prompt-state";
import type { GrantDuration, PolicyChangeRequest } from "./policy-manager.js";

export interface SandboxPromptResult {
  action: "allow" | "deny";
  /** How long the grant lasts (only when action is "allow"). */
  duration?: GrantDuration;
  /** Persistence scope for "always" approvals. */
  scope?: "workspace" | "global";
}

export interface SandboxPromptDetails {
  change: PolicyChangeRequest;
  /** The command that triggered the prompt. */
  command: string;
  promptWaitTracker?: PromptWaitTracker;
  /** Set false when persistent scopes are unsupported for this prompt. */
  allowPersistentScopes?: boolean;
  /** Set false for a strictly invocation-scoped decision. */
  allowSession?: boolean;
  /** The request is read access to folders the masked-file scan could not check. */
  unscannedRoots?: boolean;
}

const CHOICE_ONCE = "Allow once";
const CHOICE_SESSION = "Allow for session";
const CHOICE_WORKSPACE = "Allow for this workspace";
const CHOICE_GLOBAL = "Allow globally";
const CHOICE_DENY = "Deny";

/** Registered by the extension so yolo can resolve every sandbox request without a dialog. */
export interface SandboxYoloHooks {
  isYolo(): boolean;
  log(event: string, details: Record<string, unknown>): void;
}

let yoloHooks: SandboxYoloHooks | undefined;

export function setSandboxYoloHooks(hooks: SandboxYoloHooks | undefined): void {
  yoloHooks = hooks;
}

/**
 * Yolo grants network and plain path requests once, and unscanned folders for the session (a once-grant would
 * block every later command in a large folder). Everything that touches credentials or leaves the sandbox
 * (auth, host bypass, masked or protected paths) is denied.
 */
function resolveYolo(details: SandboxPromptDetails): SandboxPromptResult {
  const { change } = details;
  const grantable = (change.type === "network" || change.type === "path")
    && (details.allowPersistentScopes !== false || details.unscannedRoots === true)
    && !change.authKind;
  const duration = details.unscannedRoots ? "session" : "once";
  const result: SandboxPromptResult = grantable ? { action: "allow", duration } : { action: "deny" };
  yoloHooks?.log(grantable ? "sandbox_request.yolo_granted_once" : "sandbox_request.yolo_denied", {
    type: change.type,
    mode: change.mode ?? null,
    valueCount: change.values.length,
  });
  return result;
}

/**
 * Prompt the user for a sandbox policy change.
 * Returns the user's decision.
 */
export async function promptSandboxGrant(
  ctx: ExtensionContext,
  details: SandboxPromptDetails,
): Promise<SandboxPromptResult> {
  if (yoloHooks?.isYolo()) return resolveYolo(details);
  if (!ctx.hasUI) {
    // No UI available — default to deny (fail-closed)
    return { action: "deny" };
  }

  const {
    change,
    command,
    promptWaitTracker,
    allowPersistentScopes = true,
    allowSession = true,
  } = details;

  let title: string;
  let message: string;

  if (change.type === "network") {
    title = "⚠ Sandbox: Network Access Requested";
    message =
      `The command "${truncateCommand(command, 80)}" needs network access` +
      (change.values.length > 0
        ? ` (${change.values.join(", ")})`
        : "") +
      `, but the active sandbox profile has no network.` +
      `\n\nGrant network access?`;
  } else if (change.type === "env") {
    title = "⚠ Sandbox: CLI Authentication Requested";
    const source = (change as any).source ?? "env";
    if (source === "config-file") {
      message =
        `The command "${truncateCommand(command, 80)}" needs authentication for CLI ${change.cli ?? "unknown"}.` +
        `\nNo token env found, but auth config exists. ` +
        `\n\nApproving binds auth config files read-only for this invocation only.` +
        `\n\nGrant auth access?`;
    } else if (source === "not-found") {
      message =
        `The command "${truncateCommand(command, 80)}" needs authentication for CLI ${change.cli ?? "unknown"}.` +
        `\nNo token env or auth config was found.` +
        `\nSet a token in your shell or provide one to proceed.` +
        `\n\nGrant access attempt?`;
    } else {
      message =
        `The command "${truncateCommand(command, 80)}" requests secret env ` +
        `${change.values.join(", ")} for CLI ${change.cli ?? "unknown"}.` +
        `\n\nApproving exposes the secret to this process invocation only. Do not approve untrusted commands.` +
        `\n\nGrant secret env access?`;
    }
  } else if (change.type === "path") {
    if (change.authKind === "ssh-auth") {
      title = "⚠ Sandbox: SSH Authentication Requested";
      message = change.description;
    } else if (change.authKind === "aws-auth") {
      title = "⚠ Sandbox: AWS Authentication Requested";
      message = change.description;
    } else if (change.authKind === "kube-auth") {
      title = "⚠ Sandbox: Kubernetes Authentication Requested";
      message = change.description;
    } else if (change.authKind === "gpg-auth") {
      title = "⚠ Sandbox: GPG Signing Requested";
      message = change.description;
    } else if (change.authKind === "docker-auth") {
      title = "⚠ Sandbox: Docker Authentication Requested";
      message = change.description;
    } else {
      title = "⚠ Sandbox: Path Access Requested";
      message = change.description || (
        `The command "${truncateCommand(command, 80)}" needs ` +
        (change.mode === "rw" ? "read-write" : "read") +
        ` access to ${change.values.join(", ")}` +
        `, which is not in the current sandbox profile.` +
        `\n\nGrant path access?`
      );
    }
  } else if (change.type === "auth-bypass") {
    title = "⚠ Sandbox: Unsandboxed Authentication Required";
    message = change.description;
  } else if (change.type === "host-bypass") {
    title = allowSession
      ? "⚠ Sandbox: Host Toolchain Required"
      : "⚠ Sandbox: One-time Host Execution Requested";
    message = change.description;
  } else {
    title = "⚠ Sandbox: Policy Change Requested";
    message = change.description;
  }

  const hasWorkspaceScope = Boolean(ctx.cwd) && allowPersistentScopes;
  const options = !allowSession
    ? [CHOICE_ONCE, CHOICE_DENY]
    : change.type === "auth-bypass" || !allowPersistentScopes
      ? [CHOICE_ONCE, CHOICE_SESSION, CHOICE_DENY]
      : [
          CHOICE_ONCE,
          CHOICE_SESSION,
          ...(hasWorkspaceScope ? [CHOICE_WORKSPACE] : []),
          CHOICE_GLOBAL,
          CHOICE_DENY,
        ];

  const waitMessage =
    change.type === "host-bypass"
      ? (allowSession ? "Waiting for host toolchain approval" : "Waiting for one-time host execution approval")
      : change.type === "network"
      ? "Waiting for sandbox network approval"
      : change.type === "env"
        ? "Waiting for sandbox auth approval"
        : change.type === "auth-bypass"
          ? "Waiting for unsandboxed auth approval"
          : "Waiting for sandbox path approval";

  const promptToken = promptWaitTracker?.begin(ctx, waitMessage);
  let choice: string | undefined;
  try {
    choice = await ctx.ui.select(`${title}\n\n${message}`, options);
  } finally {
    promptWaitTracker?.end(ctx, promptToken);
  }

  if (!choice || !options.includes(choice) || choice === CHOICE_DENY) {
    return { action: "deny" };
  }

  let duration: GrantDuration;
  let scope: "workspace" | "global" | undefined;
  switch (choice) {
    case CHOICE_ONCE:
      duration = "once";
      break;
    case CHOICE_SESSION:
      duration = "session";
      break;
    case CHOICE_WORKSPACE:
      duration = "always";
      scope = "workspace";
      break;
    case CHOICE_GLOBAL:
      duration = "always";
      scope = "global";
      break;
    default:
      return { action: "deny" };
  }

  return { action: "allow", duration, scope };
}

function truncateCommand(command: string, maxLen: number): string {
  if (command.length <= maxLen) return command;
  return command.slice(0, maxLen - 3) + "...";
}