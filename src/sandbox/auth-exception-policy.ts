import { wildcardMatch } from "../wildcard-matcher.js";
import { extractTrailingSimpleCommand, type MaskedAuthKind } from "./auth-path-detection.js";
import type {
  SandboxAuthExceptionRule,
  SandboxAuthExceptionStrategy,
} from "./types.js";

export interface ResolvedAuthException {
  kind: MaskedAuthKind;
  strategy: SandboxAuthExceptionStrategy;
  matchedRule?: SandboxAuthExceptionRule;
  /** Key used for session-scoped bypass approvals. */
  approvalKey: string;
  reason: string;
}

function ruleMatches(command: string, kind: MaskedAuthKind, rule: SandboxAuthExceptionRule): boolean {
  if (!wildcardMatch(rule.match, extractTrailingSimpleCommand(command))) return false;
  if (rule.kind == null || rule.kind === "*") return true;
  return rule.kind === kind;
}

export function resolveAuthExceptionPolicy(input: {
  command: string;
  kind: MaskedAuthKind;
  rules?: SandboxAuthExceptionRule[];
  hasCandidatePaths: boolean;
  needsSocketFallback: boolean;
}): ResolvedAuthException {
  const matchedRule = (input.rules ?? []).find((rule) => ruleMatches(input.command, input.kind, rule));
  const requestedStrategy = matchedRule?.strategy
    ?? (input.needsSocketFallback
      ? "ask-bypass"
      : input.hasCandidatePaths
        ? "ask-unmask"
        : "deny");

  const strategy = input.needsSocketFallback
    ? "ask-bypass"
    : !input.hasCandidatePaths
      ? "deny"
      : requestedStrategy === "ask-bypass"
        ? "ask-bypass"
        : requestedStrategy === "deny"
          ? "deny"
          : "ask-unmask";

  const normalizedCommand = extractTrailingSimpleCommand(input.command);
  const approvalKey = matchedRule
    ? `${input.kind}:${matchedRule.match}:${strategy}`
    : `${input.kind}:${normalizedCommand}:${strategy}`;

  const reason = matchedRule
    ? `Matched auth exception rule ${matchedRule.match} (${strategy}).`
    : input.needsSocketFallback
      ? "Socket/agent-backed auth requires unsandboxed execution."
      : input.hasCandidatePaths
        ? "File-based auth is available inside sandbox via explicit read-only unmasking."
        : "No supported auth material detected for this command.";

  return {
    kind: input.kind,
    strategy,
    matchedRule,
    approvalKey,
    reason,
  };
}
