import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

import { DEFAULT_MASKED_PATTERNS } from "./masked-file-gate.js";
import { canonicalPath, expandHomePath } from "./sandbox-visible-paths.js";
import type { ResolvedSandboxProfile } from "./types.js";
import type { Rule } from "../rule.js";
import { wildcardMatch } from "../wildcard-matcher.js";

/** Ephemeral yolo visibility; never a writable or persistent path grant. */
export interface HomeReadOnlyAccess {
  path: string;
  denyPaths: string[];
  protectedPaths: string[];
}

// A glob with the same literal meaning keeps macOS deny precedence over an ancestor allow.
function literalDenyGlob(path: string): string {
  return path.replace(/([a-zA-Z0-9])$/, "[$1]");
}

export function resolveHomeReadPolicy(mode: string, rules: readonly Rule[], platform: NodeJS.Platform = process.platform): { enabled: boolean; denyPaths: string[] } {
  if (mode !== "yolo" || platform !== "darwin") return { enabled: false, denyPaths: [] };
  const home = canonicalPath(homedir());
  const denyPaths: string[] = [];
  for (const rule of rules) {
    if (rule.action !== "deny" || !["path", "external_directory", "read", "grep", "find", "ls"].some((surface) => wildcardMatch(rule.surface, surface))) continue;
    if (rule.pattern === "*.env" || rule.pattern === "*.env.*") {
      denyPaths.push(join(home, rule.pattern === "*.env" ? "**.env" : "**.env.**"));
      continue;
    }
    const path = expandHomePath(rule.pattern);
    // Unknown wildcard semantics cannot be translated safely into SRT path rules.
    if (!isAbsolute(path) || /[*?\[\]]/.test(path)) return { enabled: false, denyPaths: [] };
    const canonical = canonicalPath(path);
    if (canonical === home || home.startsWith(`${canonical}/`) || canonical === `${home}/Library`) return { enabled: false, denyPaths: [] };
    if (canonical.startsWith(`${home}/`)) denyPaths.push(path, canonical);
  }
  return { enabled: true, denyPaths };
}

export function buildHomeReadOnlyAccess(
  profile: ResolvedSandboxProfile,
  extraDenyPaths: string[] = [],
): HomeReadOnlyAccess {
  if (process.platform !== "darwin") {
    throw new Error("Yolo home reads require macOS SRT.");
  }
  if ((profile.maskedPaths ?? []).some((pattern) => /[\[\]]/.test(pattern))) {
    throw new Error("Yolo home reads cannot enforce this masked path pattern.");
  }
  const home = canonicalPath(homedir());
  const patterns = [...new Set([...DEFAULT_MASKED_PATTERNS, ...(profile.maskedPaths ?? [])])];
  const credentialPaths = [
    "Library", ".azure", ".claude/.credentials.json", ".vault-token",
    ".terraform.d/credentials.tfrc.json", ".cargo/credentials.toml", ".pgpass",
    ".config/op", ".local/share/keyrings", ".bash_history", ".zsh_history", ".zsh_sessions",
    ".python_history", ".node_repl_history", ".psql_history", ".mysql_history", ".local/share/fish",
    ".claude/projects", ".codex/sessions", ".pi/agent/sessions", ".pi/agent/extensions/pi-sentinel/logs",
  ].map((path) => join(home, path));
  const protectedPaths: string[] = credentialPaths.flatMap((path) => [path, canonicalPath(path)]);
  const nativePatterns: string[] = protectedPaths.map(literalDenyGlob);
  for (const pattern of [...patterns, ...extraDenyPaths]) {
    const expanded = expandHomePath(pattern);
    const absolute = isAbsolute(expanded) ? expanded : join(home, expanded);
    const wildcard = absolute.search(/[?*\[\]]/);
    if (wildcard === -1) {
      const canonical = canonicalPath(absolute);
      protectedPaths.push(absolute, canonical);
      nativePatterns.push(literalDenyGlob(absolute), literalDenyGlob(canonical));
    } else {
      const prefix = absolute.slice(0, wildcard);
      const base = prefix.endsWith("/") ? prefix.slice(0, -1) : dirname(prefix);
      const canonicalPattern = canonicalPath(base) + absolute.slice(base.length);
      nativePatterns.push(absolute, canonicalPattern);
      if (absolute.endsWith("/**") && !/[?*\[\]]/.test(absolute.slice(0, -3))) {
        const root = absolute.slice(0, -3);
        protectedPaths.push(root, canonicalPath(root));
        nativePatterns.push(literalDenyGlob(root), literalDenyGlob(canonicalPath(root)));
      }
    }
  }
  return {
    path: home,
    protectedPaths: [...new Set(protectedPaths)],
    denyPaths: [...new Set(nativePatterns)],
  };
}
