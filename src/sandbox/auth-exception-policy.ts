import { bashLiteralWords, bashWordsWithoutRedirections, splitBashSegments } from "../bash-segments.js";
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

function hasUninspectableSshTarget(
  kind: MaskedAuthKind,
  authCommands: string[],
  rules: SandboxAuthExceptionRule[] | undefined,
): boolean {
  if (kind !== "ssh-auth") return false;
  const hasExplicitSshDeny = (rules ?? []).some((rule) => rule.strategy === "deny"
    && (rule.kind == null || rule.kind === "*" || rule.kind === "ssh-auth"));
  return hasExplicitSshDeny && authCommands.some((authCommand) => {
    const executable = bashWordsWithoutRedirections(authCommand)?.[0]?.split("/").pop();
    const opaqueSshHereString = /\b(?:bash|sh|zsh|dash)\b[^\r\n]*<<<[^\r\n]*\b(?:ssh|scp|sftp)\b/.test(authCommand);
    const opaqueEnvSplitSsh = /\benv\b[^\r\n]*?(?:-S\b|--split-string(?:=|\s+))[^\r\n]*\b(?:ssh|scp|sftp)\b/.test(authCommand);
    return opaqueSshHereString || opaqueEnvSplitSsh
      || (["ssh", "scp", "sftp"].includes(executable ?? "") && bashLiteralWords(authCommand) === null);
  });
}

function ruleMatches(authCommand: string, kind: MaskedAuthKind, rule: SandboxAuthExceptionRule): boolean {
  const literalCommand = bashLiteralWords(authCommand)?.join(" ");
  if (!wildcardMatch(rule.match, authCommand) && (literalCommand === undefined || !wildcardMatch(rule.match, literalCommand))) {
    return false;
  }
  if (rule.kind == null || rule.kind === "*") return true;
  return rule.kind === kind;
}

export function resolveAuthExceptionPolicy(input: {
  command: string;
  kind: MaskedAuthKind;
  rules?: SandboxAuthExceptionRule[];
  hasCandidatePaths: boolean;
  needsSocketFallback: boolean;
  authCommands?: string[];
}): ResolvedAuthException {
  const authCommands = input.authCommands?.length
    ? input.authCommands
    : [extractTrailingSimpleCommand(input.command)];
  const matchedRules = authCommands.map((authCommand) => {
    const matchingRules = (input.rules ?? []).filter((rule) => ruleMatches(authCommand, input.kind, rule));
    return matchingRules.find((rule) => rule.strategy === "deny") ?? matchingRules[0];
  });
  const matchedRule = matchedRules.find((rule) => rule?.strategy === "deny")
    ?? matchedRules.find((rule) => rule !== undefined);
  const deniedByRule = matchedRules.some((rule) => rule?.strategy === "deny");
  const hasUninspectableSsh = hasUninspectableSshTarget(
    input.kind,
    authCommands,
    input.rules,
  );
  const hasMixedAuthKinds = input.kind === "generic-secret" && authCommands.length > 1;
  const hasUnsegmentableAuthCommand = Boolean(input.authCommands?.length)
    && splitBashSegments(input.command) === null;
  const allCommandsRequestBypass = matchedRules.length > 0
    && matchedRules.every((rule) => rule?.strategy === "ask-bypass");

  let strategy: SandboxAuthExceptionStrategy;
  if (
    hasMixedAuthKinds
    || hasUnsegmentableAuthCommand
    || deniedByRule
    || hasUninspectableSsh
    || (!input.hasCandidatePaths && !input.needsSocketFallback)
  ) {
    strategy = "deny";
  } else if (input.needsSocketFallback || allCommandsRequestBypass) {
    strategy = "ask-bypass";
  } else {
    strategy = "ask-unmask";
  }

  const approvalKey = `${input.kind}:${input.command.trim()}:${strategy}`;
  let reason: string;
  if (hasUnsegmentableAuthCommand) {
    reason = "Authentication commands could not be safely split; access is denied.";
  } else if (hasMixedAuthKinds) {
    reason = "Mixed authentication mechanisms cannot share one command; access is denied.";
  } else if (hasUninspectableSsh) {
    reason = "SSH target could not be normalized under an explicit deny rule; access is denied.";
  } else if (matchedRule) {
    reason = `Matched auth exception rule ${matchedRule.match} (${strategy}).`;
  } else if (input.needsSocketFallback) {
    reason = "Socket/agent-backed auth requires unsandboxed execution.";
  } else if (input.hasCandidatePaths) {
    reason = "File-based auth is available inside sandbox via explicit read-only unmasking.";
  } else {
    reason = "No supported auth material detected for this command.";
  }

  return {
    kind: input.kind,
    strategy,
    matchedRule,
    approvalKey,
    reason,
  };
}
