/**
 * Domain gate — network domain allow/deny enforcement.
 * Integrated from domain-gate.ts into pi-sentinel.
 *
 * This module provides the gate descriptor function for the PermissionGateHandler chain,
 * plus a /domain-gate command for status display.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { extractAllNetworkTargets } from "./domain-extractor.js";
import { loadDomainPolicy } from "./config.js";
import { blockedDomains } from "./domain-policy.js";
import type { DomainGateConfig, DomainCheckResult } from "./types.js";
import type { ToolCallContext } from "#src/handlers/gates/types.js";

/**
 * Is this a bash tool call event?
 */
function isBashToolCall(event: {
  toolName?: string;
  input?: unknown;
}): event is { toolName: "bash"; input: { command: string } } {
  if (event.toolName !== "bash") return false;
  const input = event.input as { command?: unknown } | undefined;
  return typeof input?.command === "string";
}

/**
 * Extract domains and check policy for a bash command.
 */
export function checkBashNetworkPolicy(
  command: string,
  networkConfig: DomainGateConfig | undefined,
  cwd: string,
  approvedDomains: readonly string[] = [],
): DomainCheckResult {
  const basePolicy = loadDomainPolicy({ network: networkConfig }, cwd);
  const policy = {
    ...basePolicy,
    allowedDomains: [...basePolicy.allowedDomains, ...approvedDomains],
  };
  const domains = extractAllNetworkTargets(command);

  if (domains.length === 0) {
    return { verdict: "allowed", blockedDomains: [], askDomains: [] };
  }

  return blockedDomains(domains, policy);
}

/**
 * Register the domain-gate command.
 */
export function registerDomainGateCommand(
  pi: ExtensionAPI,
  getNetworkConfig: (cwd?: string) => DomainGateConfig | undefined,
) {
  pi.registerCommand("domain-gate", {
    description: "Show domain-gate network allow/deny policy",
    handler: async (_args: string, ctx: ExtensionContext) => {
      const config = loadDomainPolicy({ network: getNetworkConfig(ctx.cwd) }, ctx.cwd);
      ctx.ui.notify(
        `Domain gate ${config.enabled ? "enabled" : "disabled"}\n` +
          `Default: ${config.unknownDomains === "allow" ? "allow unknown domains" : config.unknownDomains === "deny" ? "block unknown domains" : "ask for unknown domains"}\n` +
          `Allowed: ${config.allowedDomains.length ? config.allowedDomains.join(", ") : "(none)"}\n` +
          `Denied: ${config.deniedDomains.length ? config.deniedDomains.join(", ") : "(none)"}`,
        "info",
      );
    },
  });
}

export { loadDomainPolicy, blockedDomains, extractAllNetworkTargets };
export type { DomainGateConfig, DomainCheckResult };