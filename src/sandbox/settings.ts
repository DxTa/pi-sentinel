/**
 * Sandbox settings — normalize, merge, and validate.
 * Hardened from ape-dev src/lib/sandbox.ts with allowlist model.
 */

import { existsSync, lstatSync, realpathSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { resolve, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type {
  SandboxAuthExceptionRule,
  SandboxAuthExceptionStrategy,
  SandboxConfig,
  SandboxEnvPolicy,
  SandboxProfile,
  ResolvedSandboxProfile,
} from "./types.js";

export type { SandboxConfig, SandboxEnvPolicy, SandboxProfile };
import { DEFAULT_MASKED_PATTERNS } from "./masked-file-gate.js";
import { SENSITIVE_BIND_SUFFIXES, SENSITIVE_BIND_PATHS } from "./types.js";
import { awaitWithinScanBudget, isScanBudgetExceeded } from "./scan-budget.js";

const OFFLINE_DEV_PROFILE: SandboxProfile = {
  network: false,
  allowDocker: true,
  roBinds: [],
  rwBinds: [],
  env: {
    allow: ["TERM", "LANG", "LC_ALL", "LC_CTYPE", "COLORTERM", "HOME", "PATH", "TMPDIR"],
    deny: [],
  },
  maskedPaths: DEFAULT_MASKED_PATTERNS,
};

const ONLINE_DEV_PROFILE: SandboxProfile = {
  ...OFFLINE_DEV_PROFILE,
  network: true,
  allowDocker: true,
};

const DEFAULT_SANDBOX_CONFIG: SandboxConfig = {
  enabled: true,
  backend: "srt",
  profiles: {
    "offline-dev": OFFLINE_DEV_PROFILE,
    "online-dev": ONLINE_DEV_PROFILE,
  },
  defaultProfile: "online-dev",
  roBinds: [],
  rwBinds: [],
  bypassCommands: ["*"],
  authExceptions: [],
};

function dedupeStrings(values: string[]): string[] {
  const seen = new Set<string>();
  return values.filter((v) => {
    const t = v.trim();
    if (!t || seen.has(t)) return false;
    seen.add(t);
    return true;
  });
}

function coerceBindList(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  return dedupeStrings(values.map(String));
}

function coerceAuthExceptionRules(values: unknown): SandboxAuthExceptionRule[] {
  if (!Array.isArray(values)) return [];
  return values
    .filter((value): value is Record<string, unknown> => !!value && typeof value === "object")
    .map((value): SandboxAuthExceptionRule => {
      const strategy: SandboxAuthExceptionStrategy =
        value.strategy === "ask-bypass" || value.strategy === "deny"
          ? value.strategy
          : "ask-unmask";
      return {
        match: String(value.match ?? "").trim(),
        kind: value.kind == null ? undefined : String(value.kind),
        strategy,
      };
    })
    .filter((rule) => rule.match.length > 0);
}

/**
 * Normalize a raw sandbox config (from JSON) into a valid SandboxConfig.
 */
export function normalizeSandboxConfig(raw: unknown): SandboxConfig {
  if (raw === undefined) return { ...DEFAULT_SANDBOX_CONFIG };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Invalid sandbox configuration.");
  }

  const r = raw as Record<string, unknown>;
  for (const key of ["enabled", "network"] as const) {
    if (key in r && typeof r[key] !== "boolean") {
      throw new Error(`Invalid sandbox.${key}; expected boolean.`);
    }
  }

  // Merge profiles with defaults
  if (r.backend !== undefined && r.backend !== "srt") {
    throw new Error("Invalid sandbox.backend; only 'srt' is supported.");
  }

  const profiles: Record<string, SandboxProfile> = {
    ...DEFAULT_SANDBOX_CONFIG.profiles,
  };

  if (r.profiles !== undefined) {
    if (!r.profiles || typeof r.profiles !== "object" || Array.isArray(r.profiles)) {
      throw new Error("Invalid sandbox.profiles configuration.");
    }
    for (const [name, profile] of Object.entries(
      r.profiles as Record<string, unknown>,
    )) {
      if (name === "__proto__" || name === "constructor" || name === "prototype") {
        throw new Error(`Invalid sandbox profile name '${name}'.`);
      }
      if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
        throw new Error(`Invalid sandbox profile '${name}'.`);
      }
      {
        const p = profile as Record<string, unknown>;
        profiles[name] = {
          network: p.network === true,
          allowDocker: p.allowDocker === undefined ? true : p.allowDocker === true,
          roBinds: coerceBindList(p.roBinds),
          rwBinds: coerceBindList(p.rwBinds),
          env: normalizeEnvPolicy(p.env),
          maskedPaths: [...new Set([
            ...DEFAULT_MASKED_PATTERNS,
            ...(Array.isArray(p.maskedPaths) ? p.maskedPaths.filter((value): value is string => typeof value === "string") : []),
          ])],
          resourceLimits: p.resourceLimits as SandboxProfile["resourceLimits"] ?? undefined,
        };
      }
    }
  }

  return {
    enabled: r.enabled === undefined ? DEFAULT_SANDBOX_CONFIG.enabled : r.enabled === true,
    network: r.network === true,
    backend: "srt",
    profiles,
    defaultProfile: (() => {
      if (r.defaultProfile === undefined) return DEFAULT_SANDBOX_CONFIG.defaultProfile;
      if (typeof r.defaultProfile !== "string" || !Object.hasOwn(profiles, r.defaultProfile)) {
        throw new Error("Invalid sandbox.defaultProfile.");
      }
      return r.defaultProfile;
    })(),
    roBinds: coerceBindList(r.roBinds),
    rwBinds: coerceBindList(r.rwBinds),
    bypassCommands: Array.isArray(r.bypassCommands)
      ? (r.bypassCommands as string[]).map(String).filter((s) => s.length > 0)
      : [],
    authExceptions: coerceAuthExceptionRules(r.authExceptions),
  };
}

export function normalizeEnvPolicy(raw: unknown): SandboxEnvPolicy {
  const defaultPolicy: SandboxEnvPolicy = {
    allow: ["TERM", "LANG", "LC_ALL", "LC_CTYPE", "COLORTERM", "HOME", "PATH", "TMPDIR"],
    deny: [],
  };
  if (!raw || typeof raw !== "object") return defaultPolicy;

  const r = raw as Record<string, unknown>;
  return {
    allow: Array.isArray(r.allow) ? (r.allow as string[]) : defaultPolicy.allow,
    deny: Array.isArray(r.deny) ? (r.deny as string[]) : defaultPolicy.deny,
  };
}

/**
 * Sensitive bind targets — paths that must NEVER be bind-mounted.
 * Uses allowlist model: only explicitly permitted paths are allowed.
 */
function sensitiveBindTargets(): string[] {
  const home = resolve(homedir());
  const targets: string[] = [];
  for (const suffix of SENSITIVE_BIND_SUFFIXES) {
    targets.push(resolve(join(home, suffix)));
  }
  for (const p of SENSITIVE_BIND_PATHS) {
    targets.push(resolve(p));
  }
  return targets;
}

/**
 * Validate a candidate bind path against sensitive paths.
 * Throws if the path is sensitive.
 */
function isBroadSandboxPath(resolved: string): boolean {
  const home = resolve(homedir());
  return new Set([
    "/",
    "/home",
    "/Users",
    "/private",
    "/tmp",
    "/private/tmp",
    "/var",
    "/private/var",
    dirname(home),
  ]).has(resolved) || resolved === home;
}

export function validateSandboxGrantPath(candidate: string): void {
  const resolved = resolve(candidate);
  if (isBroadSandboxPath(resolved)) {
    throw new Error(`Refusing broad sandbox grant path: ${resolved}`);
  }
  validateSandboxBindPath(resolved);
}

function validateSpecialBindTarget(resolved: string): void {
  // Unix sockets are allowed. The JS realpath is used because the native one fails on sockets (EOPNOTSUPP on macOS).
  if (existsSync(resolved)) {
    const canonical = realpathSync(resolved);
    const stat = lstatSync(canonical);
    if (stat.isFIFO() || stat.isBlockDevice() || stat.isCharacterDevice()) {
      throw new Error(`Refusing special sandbox bind path: ${canonical}`);
    }
  }
}


export function validateSandboxBindPath(candidate: string): void {
  const resolved = resolve(candidate);
  const home = resolve(homedir());
  validateSpecialBindTarget(resolved);

  // Reject exact home directory itself (but not its subdirectories)
  if (resolved === home || resolved === "/" || resolved === "/home") {
    throw new Error(
      `Refusing sensitive sandbox bind path: ${resolved}`,
    );
  }

  // Reject known sensitive subdirectories
  for (const sensitive of sensitiveBindTargets()) {
    if (resolved === sensitive || resolved.startsWith(sensitive + "/")) {
      throw new Error(
        `Refusing sensitive sandbox bind path: ${resolved}`,
      );
    }
  }
}

function isMissingPathError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const code = (error as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/**
 * Resolve and validate bind paths.
 * Uses realpath to prevent symlink escapes.
 */
export function resolveSandboxBindPaths(
  values: string[],
  root: string,
): string[] {
  const resolved: string[] = [];
  for (const raw of values) {
    const text = raw.trim();
    if (!text) continue;
    const expanded = text === "~"
      ? homedir()
      : text.startsWith("~/")
        ? join(homedir(), text.slice(2))
        : text;
    const candidate = isAbsolute(expanded) ? expanded : join(root, expanded);
    const abs = resolve(candidate);
    try {
      const canonical = realpathSync.native(abs);
      validateSandboxGrantPath(canonical);
      resolved.push(canonical);
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
    }
  }
  return dedupeStrings(resolved);
}

export async function resolveSandboxBindPathsWithinScanBudget(
  values: string[],
  root: string,
  deadline: number,
  durationMs: number,
): Promise<string[]> {
  const resolved: string[] = [];
  for (const raw of values) {
    const text = raw.trim();
    if (!text) continue;
    const expanded = text === "~"
      ? homedir()
      : text.startsWith("~/")
        ? join(homedir(), text.slice(2))
        : text;
    const candidate = isAbsolute(expanded) ? expanded : join(root, expanded);
    const abs = resolve(candidate);
    try {
      const canonical = await awaitWithinScanBudget(
        realpath(abs),
        deadline,
        durationMs,
        abs,
      );
      validateSandboxGrantPath(canonical);
      resolved.push(canonical);
    } catch (error) {
      if (isScanBudgetExceeded(error)) throw error;
      if (!isMissingPathError(error)) throw error;
    }
  }
  return dedupeStrings(resolved);
}


/**
 * Resolve the active sandbox profile from config.
 */
export function resolveSandboxProfile(
  config: SandboxConfig,
  profileName?: string,
): ResolvedSandboxProfile {
  const name = profileName ?? config.defaultProfile;
  const profile = Object.hasOwn(config.profiles, name)
    ? config.profiles[name]
    : undefined;
  if (!profile) {
    throw new Error("Unknown sandbox profile '" + name + "'. Available: " + Object.keys(config.profiles).join(", "));
  }
  return { ...profile, name };
}

export { DEFAULT_SANDBOX_CONFIG };
