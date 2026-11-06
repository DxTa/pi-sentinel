/**
 * Pre-execution egress scan: flags network calls that look like data exfiltration.
 * Pure text analysis; it cannot see encoded payloads, DNS tunnels or uploads done inside a script file.
 */

import { redactSecrets } from "../secret-redaction.js";
import { extractHostsFromCommand } from "./domain-extractor.js";
import { domainMatchesPattern } from "./domain-policy.js";
import { EXFIL_DOMAINS } from "./exfil-domains.js";

export interface EgressScanInput {
  /** Bash command, or the JSON of a fetch or MCP tool input: URLs, headers and data included. */
  text: string;
  allowedDomains: readonly string[];
  deniedDomains: readonly string[];
  /** Hosts from the cached threat feed. */
  feed?: ReadonlySet<string>;
}

const URL_HOST = /\b(?:https?|wss?|ftp):\/\/(?:[^\s/@'"]*@)?(\[[0-9a-fA-F:]+\]|[^\s/:?#'"\\]+)/gi;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function urlHosts(text: string): string[] {
  return [...text.matchAll(URL_HOST)].map((match) => match[1]!.toLowerCase().replace(/\.$/, ""));
}

function isPublicIpv4(host: string): boolean {
  const match = IPV4.exec(host);
  if (!match) return false;
  const [a, b] = [Number(match[1]), Number(match[2])];
  const isPrivate = a === 10 || a === 127 || a === 0
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168);
  return !isPrivate;
}

function inFeed(host: string, feed: ReadonlySet<string>): boolean {
  const labels = host.split(".");
  return labels.some((_, index) => feed.has(labels.slice(index).join(".")));
}

/** Returns a block reason, or undefined when the call looks fine. */
export function scanEgress(input: EgressScanInput): string | undefined {
  const hosts = [...new Set([...urlHosts(input.text), ...extractHostsFromCommand(input.text)])];
  // "discord.com/api/webhooks" is path-scoped, so it is matched against the whole text.
  if (/discord(?:app)?\.com\/api\/webhooks/i.test(input.text)) return "Egress scan blocked a known exfiltration endpoint (discord webhook).";

  for (const host of hosts) {
    if (input.deniedDomains.some((pattern) => domainMatchesPattern(host, pattern))) {
      return `Egress scan blocked "${host}": it is in deniedDomains.`;
    }
    if (EXFIL_DOMAINS.some((pattern) => !pattern.includes("/") && domainMatchesPattern(host, pattern))) {
      return `Egress scan blocked "${host}": known exfiltration host (paste, tunnel or request-catcher service).`;
    }
    if (input.feed && inFeed(host, input.feed)) {
      return `Egress scan blocked "${host}": it is on the threat feed.`;
    }
    if (isPublicIpv4(host)) return `Egress scan blocked raw public IP "${host}"; use a hostname.`;
    if (host.split(".").some((label) => label.startsWith("xn--"))) {
      return `Egress scan blocked punycode host "${host}".`;
    }
  }

  const unallowed = hosts.filter((host) => !input.allowedDomains.some((pattern) => domainMatchesPattern(host, pattern)));
  if (unallowed.length > 0 && redactSecrets(input.text) !== input.text) {
    return `Egress scan blocked a secret in a request to "${unallowed[0]}". Add the host to allowedDomains if this is intended.`;
  }
  return undefined;
}
