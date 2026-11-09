/**
 * Network domain gate handler.
 *
 * Hooks into tool_call events for bash tools to check domain access policy.
 * This runs BEFORE the upstream permission gate handler.
 *
 * For user_bash events, provides BashOperations wrapping with domain check + sandbox.
 */

import type {
  ExtensionContext,
  ToolCallEvent,
  UserBashEvent,
  UserBashEventResult,
} from "@earendil-works/pi-coding-agent";
import { loadDomainPolicy } from "./config.js";
import { checkBashNetworkPolicy } from "../network/domain-gate.js";
import { scanEgress } from "./egress-scan.js";
import type { PersistentApprovalScope } from "../scoped-config";
import type { PromptWaitTracker } from "../prompt-state";
import type { DomainGateConfig } from "../network/types.js";
import { approveSessionDomains, clearSessionDomains, getSessionDomainGrants } from "./session-domains.js";

export interface NetworkGateDeps {
  getNetworkConfig: (cwd?: string) => DomainGateConfig | undefined;
  getAgentDir: () => string;
  /** Classic yolo: approve ask verdicts for this call without a prompt. Explicit denies still block. */
  autoApproveAsk?: () => boolean;
  /** Hosts from the cached threat feed, when loaded. */
  getThreatFeed?: () => ReadonlySet<string> | undefined;
  writeReviewLog?: (event: string, details: Record<string, unknown>) => void;
  promptWaitTracker?: Pick<PromptWaitTracker, "begin" | "end">;
  persistNetworkGrant?: (
    domain: string,
    scope: PersistentApprovalScope,
    state?: "allow" | "deny",
  ) => void;
  persistNetworkGrants?: (
    domains: readonly string[],
    scope: PersistentApprovalScope,
    state?: "allow" | "deny",
  ) => void;
}

export interface NetworkGateResult {
  block?: true;
  reason?: string;
  /** Domains approved by this gate for the current command/sandbox invocation. */
  approvedDomains?: string[];
}

const CHOICE_ONCE = "Allow once";
const CHOICE_SESSION = "Allow for session";
const CHOICE_DENY = "Deny";

type DomainApprovalDecision =
  | "once"
  | "session"
  | "workspace"
  | "global"
  | "host-wildcard-workspace"
  | "host-wildcard-global"
  | "parent-wildcard-workspace"
  | "parent-wildcard-global"
  | "deny-workspace"
  | "deny-global"
  | "deny";


function formatDomains(domains: readonly string[]): string {
  return domains.map((domain) => `"${domain}"`).join(", ");
}

function blockedReason(domains: readonly string[]): string {
  return `Domain gate blocked network access to ${formatDomains(domains)}. Remove from deniedDomains or configure network policy.`;
}

function noUiReason(domains: readonly string[]): string {
  return `Domain gate blocked network access to ${formatDomains(domains)} (no UI for approval).`;
}

function truncateCommand(command: string, maxLen: number): string {
  if (command.length <= maxLen) return command;
  return command.slice(0, maxLen - 3) + "...";
}

function wildcardPatterns(
  domains: readonly string[],
  kind: "host" | "parent",
): string[] | null {
  const patterns = domains.map((domain) => {
    if (/^\d+(?:\.\d+){3}$/.test(domain)) return null;
    const target = kind === "host"
      ? domain
      : domain.slice(domain.indexOf(".") + 1);
    return target.includes(".") ? `*.${target}` : null;
  });
  return patterns.every((pattern): pattern is string => pattern !== null)
    ? patterns
    : null;
}

function approvalLabel(
  verb: "Allow" | "Deny",
  patterns: readonly string[],
  scope: "project" | "global",
): string {
  const target = patterns.join(", ");
  return `${verb} ${target} ${scope === "project" ? "for this project" : "globally"}`;
}

async function promptForDomainApproval(
  ctx: ExtensionContext,
  command: string,
  domains: readonly string[],
): Promise<DomainApprovalDecision> {
  if (!ctx.hasUI) return "deny";

  const hostWildcards = wildcardPatterns(domains, "host");
  const parentWildcards = wildcardPatterns(domains, "parent");
  const exactWorkspace = approvalLabel("Allow", domains, "project");
  const exactGlobal = approvalLabel("Allow", domains, "global");
  const denyWorkspace = approvalLabel("Deny", domains, "project");
  const denyGlobal = approvalLabel("Deny", domains, "global");
  const hostWorkspace = hostWildcards && approvalLabel("Allow", hostWildcards, "project");
  const hostGlobal = hostWildcards && approvalLabel("Allow", hostWildcards, "global");
  const parentWorkspace = parentWildcards && approvalLabel("Allow", parentWildcards, "project");
  const parentGlobal = parentWildcards && approvalLabel("Allow", parentWildcards, "global");

  const choice = await ctx.ui.select(
    `⚠ Domain Gate: Network Access Requested\n\n` +
      `The command "${truncateCommand(command, 80)}" wants network access to ${formatDomains(domains)}.\n\n` +
      `Allow this network access?`,
    [
      CHOICE_ONCE,
      CHOICE_SESSION,
      ...(ctx.cwd ? [exactWorkspace, hostWorkspace, parentWorkspace, denyWorkspace].filter(Boolean) : []),
      exactGlobal,
      hostGlobal,
      parentGlobal,
      CHOICE_DENY,
      denyGlobal,
    ].filter((option): option is string => Boolean(option)),
  );

  if (choice === CHOICE_ONCE) return "once";
  if (choice === CHOICE_SESSION) return "session";
  if (choice === exactWorkspace) return "workspace";
  if (choice === exactGlobal) return "global";
  if (choice === hostWorkspace) return "host-wildcard-workspace";
  if (choice === hostGlobal) return "host-wildcard-global";
  if (choice === parentWorkspace) return "parent-wildcard-workspace";
  if (choice === parentGlobal) return "parent-wildcard-global";
  if (choice === denyWorkspace) return "deny-workspace";
  if (choice === denyGlobal) return "deny-global";
  return "deny";
}

async function resolveAskVerdict(
  ctx: ExtensionContext,
  command: string,
  domains: readonly string[],
  deps: NetworkGateDeps,
): Promise<NetworkGateResult | undefined> {
  if (domains.length === 0) return undefined;
  if (deps.autoApproveAsk?.()) return { approvedDomains: [...domains] };
  if (!ctx.hasUI) {
    return { block: true, reason: noUiReason(domains) };
  }

  const promptToken = deps.promptWaitTracker?.begin(ctx, "Waiting for domain approval");
  let decision: Awaited<ReturnType<typeof promptForDomainApproval>>;
  try {
    decision = await promptForDomainApproval(ctx, command, domains);
  } finally {
    deps.promptWaitTracker?.end(ctx, promptToken);
  }
  const denyScope = decision === "deny-workspace"
    ? "workspace"
    : decision === "deny-global"
      ? "global"
      : null;
  if (decision === "deny" || denyScope) {
    if (denyScope) {
      try {
        if (deps.persistNetworkGrants) {
          deps.persistNetworkGrants(domains, denyScope, "deny");
        } else {
          for (const domain of domains) {
            deps.persistNetworkGrant?.(domain, denyScope, "deny");
          }
        }
      } catch {
        return { block: true, reason: "Domain gate: failed to persist denial; command blocked." };
      }
    }
    return { block: true, reason: `Domain gate: user denied network access to ${formatDomains(domains)}.` };
  }

  const wildcardKind = decision.startsWith("host-wildcard")
    ? "host"
    : decision.startsWith("parent-wildcard")
      ? "parent"
      : null;
  const persistScope = decision.endsWith("workspace")
    ? "workspace"
    : decision.endsWith("global")
      ? "global"
      : null;
  const patterns = wildcardKind
    ? wildcardPatterns(domains, wildcardKind) ?? [...domains]
    : [...domains];

  if (persistScope) {
    try {
      if (deps.persistNetworkGrants) {
        deps.persistNetworkGrants(patterns, persistScope);
      } else {
        for (const pattern of patterns) {
          deps.persistNetworkGrant?.(pattern, persistScope);
        }
      }
    } catch {
      return { block: true, reason: "Domain gate: failed to persist approval; command blocked." };
    }
  }
  if (decision !== "once") {
    approveSessionDomains(domains);
  }

  return { approvedDomains: [...domains] };
}

export function getSessionNetworkApprovals(): string[] {
  return getSessionDomainGrants().allowed;
}

/** Text a network-capable tool call sends out: the bash command, or the JSON of a fetch or MCP input. */
function egressText(toolName: string, input: unknown): string | undefined {
  if (toolName === "bash") {
    const command = (input as { command?: unknown } | undefined)?.command;
    return typeof command === "string" ? command : undefined;
  }
  return toolName === "web_fetch" || toolName.startsWith("mcp") ? JSON.stringify(input ?? {}) : undefined;
}

/** Runs the egress scan on a call's URLs, headers and data. Applies in every mode, whatever the domain policy says. */
function egressBlockReason(text: string, cwd: string, deps: NetworkGateDeps): string | undefined {
  const policy = loadDomainPolicy({ network: deps.getNetworkConfig(cwd) });
  return scanEgress({
    text,
    allowedDomains: policy.allowedDomains,
    deniedDomains: policy.deniedDomains,
    feed: deps.getThreatFeed?.(),
  });
}

/**
 * Handle tool_call events for network domain gating.
 * Returns {block: true, reason} if domains are denied, undefined to allow.
 */
export async function handleNetworkToolCall(
  event: ToolCallEvent,
  ctx: ExtensionContext,
  deps: NetworkGateDeps,
): Promise<NetworkGateResult | undefined> {
  const text = egressText(event.toolName, event.input);
  if (text === undefined) return undefined;
  const egressReason = egressBlockReason(text, ctx.cwd, deps);
  if (egressReason) {
    deps.writeReviewLog?.("network_gate.egress_blocked", { toolName: event.toolName, reason: egressReason });
    return { block: true, reason: egressReason };
  }
  if (event.toolName !== "bash") return undefined;

  const command = text;

  const result = checkBashNetworkPolicy(
    command,
    deps.getNetworkConfig(ctx.cwd),
    ctx.cwd,
    getSessionDomainGrants().allowed,
  );

  if (result.verdict === "denied" && result.blockedDomains.length > 0) {
    return {
      block: true,
      reason: result.reason ?? blockedReason(result.blockedDomains),
    };
  }

  if (result.verdict === "ask" && result.askDomains && result.askDomains.length > 0) {
    return resolveAskVerdict(ctx, command, result.askDomains, deps);
  }

  return undefined;
}

/**
 * Handle user_bash events for network domain gating.
 * Returns a UserBashEventResult with exitCode 1 if domains are denied.
 */
export async function handleNetworkUserBash(
  event: UserBashEvent,
  ctx: ExtensionContext,
  deps: NetworkGateDeps,
): Promise<(UserBashEventResult & { approvedDomains?: string[] }) | undefined> {
  const egressReason = egressBlockReason(event.command, event.cwd, deps);
  if (egressReason) {
    deps.writeReviewLog?.("network_gate.egress_blocked", { toolName: "user_bash", reason: egressReason });
    return { result: { output: `${egressReason}\n`, exitCode: 1, cancelled: false, truncated: false } };
  }
  const result = checkBashNetworkPolicy(
    event.command,
    deps.getNetworkConfig(event.cwd),
    event.cwd,
    getSessionDomainGrants().allowed,
  );

  if (result.verdict === "denied" && result.blockedDomains.length > 0) {
    return {
      result: {
        output: `${result.reason ?? blockedReason(result.blockedDomains)}\n`,
        exitCode: 1,
        cancelled: false,
        truncated: false,
      },
    };
  }

  if (result.verdict === "ask" && result.askDomains && result.askDomains.length > 0) {
    const promptResult = await resolveAskVerdict(ctx, event.command, result.askDomains, deps);
    if (promptResult?.block) {
      return {
        result: {
          output: `${promptResult.reason}\n`,
          exitCode: 1,
          cancelled: false,
          truncated: false,
        },
      };
    }
    return { approvedDomains: promptResult?.approvedDomains ?? [] };
  }

  return undefined;
}

export function clearSessionNetworkApprovals(): void {
  clearSessionDomains();
}
