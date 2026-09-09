/**
 * SandboxPolicyManager — Dynamic sandbox rule management.
 *
 * Manages sandbox profiles with runtime grants:
 * - Session grants (in-memory, expire at session end)
 * - Temporary grants (in-memory, expire after TTL)
 * - Persistent grants (saved to the selected permissions.json override)
 *
 * Uses the same ask/allow/deny UX pattern as the upstream permission system.
 */

import type { SandboxConfig, SandboxProfile, ResolvedSandboxProfile } from "./types.js";
import { normalizeSandboxConfig, resolveSandboxProfile, validateSandboxGrantPath } from "./settings.js";
import { DEFAULT_MASKED_PATTERNS, isPathMasked } from "./masked-file-gate.js";
import { existsSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { extractAllNetworkTargets } from "../network/domain-extractor.js";

// ── Grant Types ──────────────────────────────────────────────────────────

export type GrantType = "network" | "path" | "env";

export interface Grant {
  id: string;
  type: GrantType;
  /** For network grants: domain patterns. For path grants: filesystem paths. For env grants: CLI name. */
  value: string;
  /** For path grants: read-only or read-write. */
  mode?: "ro" | "rw";
  /** For env grants: environment variable name granted to the CLI in value. */
  envName?: string;
  /** Project/workspace scope for this live grant. */
  projectRoot?: string;
  /** When the grant expires (null = session end). */
  expiresAt: Date | null;
  /** When the grant was created. */
  createdAt: Date;
}

export type GrantDuration = "once" | "session" | "always" | number; // number = ms TTL

export interface PolicyChangeRequest {
  type: GrantType | "auth-bypass";
  /** Human-readable description of what's needed. */
  description: string;
  /** Domain patterns, paths, or auth-exception values. */
  values: string[];
  /** For path grants: read or write access. */
  mode?: "ro" | "rw";
  /** For env grants: CLI executable name. */
  cli?: string;
  /** For env grants: auth source type. */
  source?: "env" | "config-file" | "not-found";
  /** Optional auth-sensitive path classification (SSH/AWS/etc.) for richer prompt copy. */
  authKind?: string;
  /** For env grants: project root scope. */
  projectRoot?: string;
}

export interface ResolvedProfile {
  profile: ResolvedSandboxProfile;
  /** Grants that were applied to reach this profile. */
  activeGrants: Grant[];
  /** Whether the command can execute with this profile. */
  canExecute: boolean;
  /** If canExecute is false, describes what's needed. */
  requiredChanges?: PolicyChangeRequest;
}

// ── SandboxPolicyManager ──────────────────────────────────────────────────

function resolveGrantPath(path: string): string {
  const normalized = resolve(path);
  validateSandboxGrantPath(normalized);
  if (!existsSync(normalized)) return normalized;
  const canonical = realpathSync.native(normalized);
  validateSandboxGrantPath(canonical);
  return canonical;
}

let grantCounter = 0;

export class SandboxPolicyManager {
  private config: SandboxConfig;
  private grants: Map<string, Grant> = new Map();
  private domainCache: Map<string, "allowed" | "denied"> = new Map();
  private timerHandle: ReturnType<typeof setInterval> | null = null;

  constructor(config: SandboxConfig) {
    this.config = normalizeSandboxConfig(config);
    // Start grant expiry timer
    this.timerHandle = setInterval(() => this.evictExpiredGrants(), 30_000);
  }

  destroy(): void {
    if (this.timerHandle) {
      clearInterval(this.timerHandle);
      this.timerHandle = null;
    }
  }

  // ── Config access ─────────────────────────────────────────────────────

  getConfig(): SandboxConfig {
    return this.config;
  }

  updateConfig(config: SandboxConfig): void {
    this.config = normalizeSandboxConfig(config);
  }

  // ── Grant management ────────────────────────────────────────────────────

  /**
   * Grant network access for specified domains.
   */
  grantNetwork(
    domains: string[],
    opts: { duration?: GrantDuration; projectRoot?: string } = {},
  ): Grant[] {
    const grants: Grant[] = [];
    for (const domain of domains) {
      const id = `grant-${++grantCounter}`;
      const expiresAt = this.computeExpiry(opts.duration);
      const grant: Grant = {
        id,
        type: "network",
        value: domain,
        expiresAt,
        projectRoot: opts.projectRoot,
        createdAt: new Date(),
      };
      this.grants.set(id, grant);
      this.domainCache.set(domain, "allowed");
      grants.push(grant);
    }
    return grants;
  }

  /**
   * Grant path access.
   */
  grantPath(
    path: string,
    mode: "ro" | "rw",
    opts: { duration?: GrantDuration; projectRoot?: string } = {},
  ): Grant {
    const normalizedPath = resolveGrantPath(path);
    const profile = resolveSandboxProfile(this.config, this.config.defaultProfile);
    const masked = isPathMasked(normalizedPath, [...DEFAULT_MASKED_PATTERNS, ...(profile.maskedPaths ?? [])]);
    if (mode === "rw" && masked) {
      throw new Error(`Refusing read-write grant to protected credential path: ${normalizedPath}`);
    }
    if (!masked) validateSandboxGrantPath(normalizedPath);
    const id = `grant-${++grantCounter}`;
    const expiresAt = this.computeExpiry(opts.duration);
    const grant: Grant = {
      id,
      type: "path",
      value: normalizedPath,
      mode,
      expiresAt,
      projectRoot: opts.projectRoot,
      createdAt: new Date(),
    };
    this.grants.set(id, grant);
    return grant;
  }

  /**
   * Grant command-scoped access to an environment variable for a specific CLI.
   * Stores only the env var name, never its value.
   */
  grantEnv(
    cli: string,
    envName: string,
    opts: { duration?: GrantDuration; projectRoot?: string } = {},
  ): Grant {
    const id = `grant-${++grantCounter}`;
    const expiresAt = this.computeExpiry(opts.duration);
    const grant: Grant = {
      id,
      type: "env",
      value: cli,
      envName,
      projectRoot: opts.projectRoot,
      expiresAt,
      createdAt: new Date(),
    };
    this.grants.set(id, grant);
    return grant;
  }

  /**
   * Revoke a specific grant.
   */
  revokeGrant(id: string): boolean {
    const grant = this.grants.get(id);
    if (!grant) return false;
    this.grants.delete(id);
    if (grant.type === "network") {
      this.domainCache.delete(grant.value);
    }
    return true;
  }

  /**
   * Clear all in-memory grants at session end.
   * Persistent approvals are reloaded from config on the next resolution.
   */
  clearGrants(): void {
    this.grants.clear();
    this.domainCache.clear();
  }

  /**
   * List all active grants.
   */
  listGrants(scopeRoot?: string): Grant[] {
    return [...this.grants.values()].filter((grant) =>
      !this.isExpired(grant) && this.isGrantInScope(grant, scopeRoot),
    );
  }

  // ── Profile resolution ──────────────────────────────────────────────────

  /**
   * Resolve the effective sandbox profile for a command.
   * Applies session/temporary grants on top of the base config profile.
   */
  resolveProfile(
    command: string,
    cwd: string,
    scopeRoot?: string,
    opts: {
      network?: boolean;
      pathGrants?: { path: string; mode: "ro" | "rw" }[];
    } = {},
  ): ResolvedProfile {
    // Start with base profile
    const baseName = this.config.defaultProfile;
    let profile = resolveSandboxProfile(this.config, baseName);

    // Check if any network grants apply
    const activeGrants: Grant[] = [];
    let hasNetworkGrant = this.config.network === true || opts.network === true;
    let hasPathGrants: { ro: string[]; rw: string[] } = { ro: [], rw: [] };
    for (const grant of opts.pathGrants ?? []) {
      if (isPathMasked(grant.path, profile.maskedPaths ?? [])) continue;
      if (!existsSync(grant.path)) continue;
      hasPathGrants[grant.mode].push(grant.path);
    }

    for (const grant of this.grants.values()) {
      if (this.isExpired(grant) || !this.isGrantInScope(grant, scopeRoot ?? cwd)) continue;
      activeGrants.push(grant);
      if (grant.type === "network") {
        hasNetworkGrant = true;
      }
      if (grant.type === "path") {
        // Do not apply grants for masked/sensitive paths as generic profile
        // binds. Masked-file approvals are command-scoped in index.ts via
        // unmaskedPaths, so unrelated later commands cannot accidentally try
        // to bind ~/.ssh/id_rsa, .env, *.pem, etc. into every sandbox.
        if (isPathMasked(grant.value, profile.maskedPaths ?? [])) continue;
        if (!existsSync(grant.value)) continue;
        if (grant.mode === "ro") {
          hasPathGrants.ro.push(grant.value);
        }
        if (grant.mode === "rw") {
          hasPathGrants.rw.push(grant.value);
        }
      }
    }

    // Apply network grant without changing unrelated profile restrictions.
    if (hasNetworkGrant && !profile.network) {
      profile = { ...profile, network: true, name: `${profile.name}+network` };
    }

    // Apply path grants
    if (hasPathGrants.ro.length > 0 || hasPathGrants.rw.length > 0) {
      profile = {
        ...profile,
        name: `${profile.name}+grants`,
        roBinds: [...(profile.roBinds ?? []), ...hasPathGrants.ro],
        rwBinds: [...(profile.rwBinds ?? []), ...hasPathGrants.rw],
      };
    }

    // Check if command needs policy changes
    const requiredChanges = this.checkPolicyNeeds(command, profile);

    return {
      profile,
      activeGrants,
      canExecute: requiredChanges === null,
      requiredChanges: requiredChanges ?? undefined,
    };
  }

  /**
   * Check if a command needs policy changes that aren't covered by current profile + grants.
   */
  private checkPolicyNeeds(
    command: string,
    profile: ResolvedSandboxProfile,
  ): PolicyChangeRequest | null {
    if (!profile.network) {
      const targets = extractAllNetworkTargets(command);
      if (targets.length > 0) {
        return {
          type: "network",
          description: `Network access required for ${targets.join(", ")}`,
          values: targets,
        };
      }
    }

    return null;
  }

  // ── Domain cache ────────────────────────────────────────────────────────

  getCachedDomainVerdict(domain: string): "allowed" | "denied" | undefined {
    return this.domainCache.get(domain);
  }

  cacheDomainVerdict(domain: string, verdict: "allowed" | "denied"): void {
    this.domainCache.set(domain, verdict);
  }

  // ── Persistent config ──────────────────────────────────────────────────

  /**
   * Save a grant to persistent config (for "always" choices).
   * This writes to the selected permissions.json override.
   */
  saveNetworkGrantToConfig(domain: string): void {
    // This will be implemented with actual config file writing
    // in the integration phase
    console.log(
      `[pi-sentinel] Saving persistent network grant: ${domain}`,
    );
  }

  savePathGrantToConfig(path: string, mode: "ro" | "rw"): void {
    console.log(
      `[pi-sentinel] Saving persistent path grant: ${mode} ${path}`,
    );
  }

  // ── Internal ────────────────────────────────────────────────────────────

  private computeExpiry(duration?: GrantDuration): Date | null {
    if (duration === "once") return new Date(Date.now() + 60_000); // once = expires quickly
    if (duration === "session" || duration === "always" || duration === undefined) return null; // session end
    if (typeof duration === "number") return new Date(Date.now() + duration);
    return null;
  }

  private isExpired(grant: Grant): boolean {
    if (grant.expiresAt === null) return false;
    return Date.now() > grant.expiresAt.getTime();
  }

  private isGrantInScope(grant: Grant, scopeRoot?: string): boolean {
    return !grant.projectRoot || !scopeRoot || resolve(grant.projectRoot) === resolve(scopeRoot);
  }

  private evictExpiredGrants(): void {
    for (const [id, grant] of this.grants.entries()) {
      if (this.isExpired(grant)) {
        this.grants.delete(id);
        if (grant.type === "network") {
          this.domainCache.delete(grant.value);
        }
      }
    }
  }
}