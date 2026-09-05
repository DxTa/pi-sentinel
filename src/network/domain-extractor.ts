/**
 * Extract domain names from command strings.
 * Ported from domain-gate.ts.
 */

/**
 * Extract domains from URLs in a command string.
 * Catches http:// and https:// URLs.
 */
export function extractDomainsFromCommand(command: string): string[] {
  const domains = new Set<string>();
  const urlRegex =
    /https?:\/\/((?:localhost|[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}))(?::\d+)?(?:[/?#]|\s|$)/g;
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(command)) !== null) {
    domains.add(match[1].toLowerCase());
  }
  return [...domains];
}

/**
 * Extract SSH-style hostnames from command strings.
 * Catches ssh://, git://, scp-style host arguments.
 */
export function extractHostsFromCommand(command: string): string[] {
  const domains = new Set<string>();
  // ssh://host, git://host
  const schemeRegex = /(?:ssh|git):\/\/((?:localhost|[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}))(?::\d+)?(?:[/?#]|\s|$)/g;
  let match: RegExpExecArray | null;
  while ((match = schemeRegex.exec(command)) !== null) {
    domains.add(match[1].toLowerCase());
  }
  // scp-style: user@host:port, user@host:/path
  const scpRegex = /\b([a-zA-Z0-9._-]+)@((?:localhost|[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}))(?::\d+)?:/g;
  while ((match = scpRegex.exec(command)) !== null) {
    domains.add(match[2].toLowerCase());
  }
  return [...domains];
}

/**
 * Extract IP addresses from command strings.
 */
export function extractIpsFromCommand(command: string): string[] {
  const ips = new Set<string>();
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  let match: RegExpExecArray | null;
  while ((match = ipRegex.exec(command)) !== null) {
    ips.add(match[1]);
  }
  return [...ips];
}

/**
 * Extract all network targets from a command (URLs, hosts, IPs).
 */
export function extractAllNetworkTargets(command: string): string[] {
  const targets = new Set<string>();
  for (const d of extractDomainsFromCommand(command)) targets.add(d);
  for (const h of extractHostsFromCommand(command)) targets.add(h);
  for (const ip of extractIpsFromCommand(command)) targets.add(ip);
  return [...targets];
}