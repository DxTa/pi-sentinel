/**
 * Session-scoped domain grants. In memory only; cleared on session shutdown.
 * `loadDomainPolicy` merges these into every policy, so all gates see one view.
 */
const allowedDomains = new Set<string>();
const deniedDomains = new Set<string>();

export function approveSessionDomains(domains: readonly string[]): void {
  for (const domain of domains) allowedDomains.add(domain);
}

export function denySessionDomains(domains: readonly string[]): void {
  for (const domain of domains) deniedDomains.add(domain);
}

export function removeSessionDomain(domain: string): void {
  allowedDomains.delete(domain);
  deniedDomains.delete(domain);
}

export function getSessionDomainGrants(): { allowed: string[]; denied: string[] } {
  return { allowed: [...allowedDomains], denied: [...deniedDomains] };
}

export function clearSessionDomains(): void {
  allowedDomains.clear();
  deniedDomains.clear();
}
