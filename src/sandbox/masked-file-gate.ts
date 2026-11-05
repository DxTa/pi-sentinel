/**
 * Masked file access gate for sandbox.
 *
 * When a command references a file that would be masked by the sandbox
 * (replaced with a "(masked)" content placeholder), this gate detects
 * the access BEFORE the command runs and prompts the user for permission.
 *
 * Masking behavior:
 * - Directory listings (`ls`, `find`) still show filenames — only file
 *   *content* is replaced with "(masked)".
 * - `cat`, `grep`, `rg` on masked files see "(masked)" instead of secrets.
 * - `find` by name is safe and works normally since filenames are visible.
 * - `grep`/`rg` won't match secret content (it's replaced), but searching
 *   for "(masked)" would match all masked files — which is expected.
 *
 * This provides the same interactive UX as other permission rules
 * (bash path, external directory) rather than silently returning empty data.
 */

import { homedir } from "node:os";
import { resolve, join, basename, dirname, sep } from "node:path";
import { existsSync } from "node:fs";
import type { SandboxProfile, UnmaskedPath } from "./types.js";
import { canonicalPath, normalizeMacPrivatePath } from "./sandbox-visible-paths.js";
import { isSensitiveEnvPath, isWorkspaceLocalFileOperation } from "../path-utils.js";
import type { MaskedAuthKind } from "./auth-path-detection.js";

/**
 * Default masked path patterns (same as in settings.ts OFFLINE_DEV_PROFILE).
 */
export const DEFAULT_MASKED_PATTERNS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  "**/credentials.json",
  "**/credentials.db",
  "**/token.json",
  "**/auth.json",
  "**/auth-token.json",
  "**/secrets.json",
  "**/passwords.json",
  "~/.ssh/**",
  "~/.aws/**",
  "~/.gnupg/**",
  "~/.kube/**",
  "~/.docker/**",
  "~/.git-credentials",
  "~/.config/git/credentials",
  "~/.config/gh/hosts.yml",
  "~/.config/gcloud/**",
  "~/.config/azure/**",
  "~/.config/claude/**",
  "~/.config/codex/**",
  "~/.config/anthropic/**",
  "~/.config/openai/**",
  "~/.config/rclone/**",
  "~/.config/glab-cli/**",
  "~/.config/pypoetry/**",
  "~/.config/pip/**",
  "~/.npmrc",
  "~/.pypirc",
  "~/.netrc",
  "~/.pi/agent/auth.json",
  "~/.pi/agent/mcp-auth.json",
  "~/.pi/agent/mcp.json",
  "~/.pi/agent/models.json",
  "~/.pi/agent/search-config.json",
  "~/.config/github-copilot/**",
  "~/.config/acli/**",
  "~/.config/Claude/**",
];

/**
 * Simple glob-to-regex converter for masked path matching.
 * Supports: *, **, ?, and literal characters.
 */
function globToRegex(pattern: string): RegExp {
  let regex = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")  // Escape regex specials (except * and ?)
    .replace(/\*\*/g, "§§GLOBSTAR§§")         // Preserve ** temporarily
    .replace(/\*/g, "[^/]*")                  // * matches anything except /
    .replace(/§§GLOBSTAR§§/g, ".*")          // ** matches anything including /
    .replace(/\?/g, "[^/]");                  // ? matches single char
  return new RegExp(`^${regex}$`);
}

/**
 * Expand ~ to the home directory.
 */
function expandHome(path: string): string {
  if (path.startsWith("~/")) {
    return join(homedir(), path.slice(2));
  }
  if (path === "~") {
    return homedir();
  }
  return path;
}

function normalizeHomeAlias(filePath: string): string {
  const home = homedir();
  const canonicalHome = canonicalPath(home);
  const resolvedFilePath = resolve(filePath);
  const canonicalParent = canonicalPath(dirname(resolvedFilePath));
  const canonicalFilePath = join(canonicalParent, basename(resolvedFilePath));
  const homePrefix = canonicalHome + sep;
  return canonicalFilePath.startsWith(homePrefix)
    ? join(home, canonicalFilePath.slice(homePrefix.length))
    : canonicalFilePath;
}

/**
 * Check if a resolved path matches any masked pattern.
 */
export function isPathMasked(filePath: string, patterns: string[]): boolean {
  const candidatePaths = [...new Set([
    filePath,
    normalizeMacPrivatePath(filePath),
    normalizeHomeAlias(filePath),
  ])];
  const regexes = patterns.map((p) => {
    const expanded = normalizeMacPrivatePath(expandHome(p));
    return globToRegex(expanded);
  });

  return regexes.some((regex) => candidatePaths.some((candidatePath) => regex.test(candidatePath)));
}

/**
 * Detect masked file access in a bash command string.
 *
 * This uses a multi-strategy approach:
 * 1. Docker `--env-file` operands, including quoted values
 * 2. Token splitting for path-like tokens and bare names such as .env.local
 * 3. Environment variable expansion for $HOME forms
 *
 * Returns the list of masked file paths referenced by the command,
 * or an empty array if no masked paths are referenced.
 */
export interface MaskedFileAccessOptions {
  /** Include protected path references that do not exist yet (write preflight). */
  includeMissing?: boolean;
}

function collectDockerEnvFileCandidates(command: string, cwd: string): string[] {
  const candidates: string[] = [];
  // Preserve quoted option values that the general token split would separate.
  const envFileOption = /(?:^|\s)--env-file(?:=|\s+)(?:"([^"]*)"|'([^']*)'|([^\s;&|<>]+))/g;
  for (const match of command.matchAll(envFileOption)) {
    const value = match[1] ?? match[2] ?? match[3];
    if (!value) continue;
    const expanded = expandHome(value);
    candidates.push(expanded.startsWith("/") ? expanded : resolve(cwd, expanded));
  }
  return candidates;
}

function getTokenPathCandidates(token: string, cwd: string): string[] {
  if (token.startsWith("--") && token.includes("=")) {
    const value = token.slice(token.indexOf("=") + 1);
    if (!value) return [];
    const expanded = expandHome(value);
    return [expanded.startsWith("/") ? expanded : resolve(cwd, expanded)];
  }

  // Skip if it looks like a flag or command
  if (token.startsWith("-")) return [];
  if (/^(sudo|bash|sh|zsh|cat|head|tail|less|more|grep|sed|awk|find|ls|cd|cp|mv|rm|echo|printenv|env|which|type|file|stat|readlink|md5sum|sha256sum|wc|sort|uniq|cut|comm|diff|tar|unzip|gzip|python|python3|node|ruby|perl|vim|vi|nano|code|source|exec|xargs|tee|curl|wget|docker|git|npm|yarn|pnpm|npx|pip|make|cmake|cargo|go|java|javac|dotnet)$/.test(token)) return [];

  const candidates: string[] = [];
  // Path-like tokens: starts with /, ~, ., or contains /
  if (token.startsWith("/") || token.startsWith("~") || token.startsWith("./") || token.startsWith("../") || token.includes("/")) {
    const expanded = expandHome(token);
    candidates.push(expanded.startsWith("/") ? expanded : resolve(cwd, expanded));
  }

  // A bare relative name (".env.local", "token.json") is matched against the patterns too.
  if (!token.includes("/")) candidates.push(resolve(cwd, token));
  return candidates;
}

function collectTokenPathCandidates(command: string, cwd: string): string[] {
  const tokens = command
    .split(/[\s;|&<>`$\\'"!\n\r\t]+/)
    .filter((token) => token.length > 0);
  const candidates: string[] = [];
  for (const token of tokens) candidates.push(...getTokenPathCandidates(token, cwd));
  return candidates;
}

function collectHomeExpansionCandidates(command: string): string[] {
  const home = homedir();
  const envExpanded = command
    .replace(/\$HOME/g, home)
    .replace(/\$\{HOME\}/g, home)
    .replace(/\$\{HOME%\/\}/g, home.replace(/\/$/, ""));

  const tokens = envExpanded
    .split(/[\s;|&<>`$\\'"!\n\r\t]+/)
    .filter((token) => token.length > 1 && token.startsWith("/"));
  return tokens;
}

function collectCommandPathCandidates(command: string, cwd: string): string[] {
  return [...new Set([
    ...collectDockerEnvFileCandidates(command, cwd),
    ...collectTokenPathCandidates(command, cwd),
    ...collectHomeExpansionCandidates(command),
  ])];
}

export function detectMaskedFileAccess(
  command: string,
  profile: Pick<SandboxProfile, "maskedPaths">,
  cwd: string,
  options: MaskedFileAccessOptions = {},
): string[] {
  const patterns = profile.maskedPaths?.length
    ? profile.maskedPaths
    : DEFAULT_MASKED_PATTERNS;

  const uniqueCandidates = collectCommandPathCandidates(command, cwd);

  // Check each candidate against masked patterns and existence
  const matchedPaths: string[] = [];
  for (const path of uniqueCandidates) {
    const workspaceDotenv = isSensitiveEnvPath(path, cwd)
      && isWorkspaceLocalFileOperation("read", { path }, cwd, { allowWorkspaceEnvRead: true });
    if (
      (isPathMasked(path, patterns) || workspaceDotenv)
      && (options.includeMissing === true || existsSync(path))
    ) {
      matchedPaths.push(path);
    }
  }

  return [...new Set(matchedPaths)];
}

/**
 * Check if a command would access masked files and return prompt details.
 * Returns null if no masked access detected, or prompt info if detected.
 *
 * @param existingGrants - Set of paths that are already granted for this session,
 *   to avoid double-prompting the user.
 */
export function classifyMaskedPathKind(paths: string[]): MaskedAuthKind {
  if (paths.some((path) => path.startsWith(resolve(homedir(), ".gnupg") + "/"))) return "gpg-auth";
  if (paths.some((path) => path.startsWith(resolve(homedir(), ".ssh") + "/"))) return "ssh-auth";
  if (paths.some((path) => path.startsWith(resolve(homedir(), ".aws") + "/"))) return "aws-auth";
  if (paths.some((path) => path.startsWith(resolve(homedir(), ".kube") + "/"))) return "kube-auth";
  if (paths.some((path) => path.startsWith(resolve(homedir(), ".docker") + "/"))) return "docker-auth";
  return "generic-secret";
}

export function formatMaskedAccessSuggestion(
  command: string,
  maskedPaths: string[],
  kind: MaskedAuthKind,
): string {
  const fileList = maskedPaths.length === 1
    ? maskedPaths[0]
    : maskedPaths.slice(0, 3).join(", ") + (maskedPaths.length > 3 ? ` and ${maskedPaths.length - 3} more` : "");

  if (kind === "gpg-auth") {
    return `The command "${command}" needs GPG signing access (gpg-agent / ~/.gnupg). Granting bypass runs it outside the sandbox.`;
  }
  if (kind === "ssh-auth") {
    return `The command \"${command}\" needs read access to SSH auth files: ${fileList}. Granting access exposes them read-only inside the sandbox for the selected duration.`;
  }
  if (kind === "aws-auth") {
    return `The command \"${command}\" needs read access to AWS auth/config files: ${fileList}. Granting access exposes them read-only inside the sandbox for the selected duration.`;
  }
  if (kind === "kube-auth") {
    return `The command \"${command}\" needs read access to Kubernetes auth/config files: ${fileList}. Granting access exposes them read-only inside the sandbox for the selected duration.`;
  }
  if (kind === "docker-auth") {
    return `The command \"${command}\" needs read access to Docker auth/config files: ${fileList}. Granting access exposes them read-only inside the sandbox for the selected duration.`;
  }

  return `The sandbox masks these protected files with \"(masked)\" content: ${fileList}. Granting access will make them readable (not writable) inside the sandbox. Without access, cat/grep will see \"(masked)\" instead of real content, and directory listings (ls/find) will still show filenames.`;
}

export function checkMaskedFileAccess(
  command: string,
  profile: SandboxProfile,
  cwd: string,
  existingGrants?: Set<string>,
): MaskedFilePromptInfo | null {
  const masked = detectMaskedFileAccess(command, profile, cwd);

  // Filter out already-granted paths to avoid double-prompting
  const ungranted = existingGrants
    ? masked.filter((p) => !existingGrants.has(p))
    : masked;

  if (ungranted.length === 0) return null;
  const kind = classifyMaskedPathKind(ungranted);

  return {
    command,
    maskedPaths: ungranted,
    allMaskedPaths: masked,
    authKind: kind,
    suggestion: formatMaskedAccessSuggestion(command, ungranted, kind),
  };
}

export interface MaskedFilePromptInfo {
  /** The command that triggered the detection. */
  command: string;
  /** The masked file paths that are not yet granted (need user approval). */
  maskedPaths: string[];
  /** All masked file paths detected (including already-granted ones). */
  allMaskedPaths: string[];
  /** Best-effort classification for auth-aware prompts. */
  authKind: MaskedAuthKind;
  /** Suggestion for the user. */
  suggestion: string;
}

/**
 * Convert masked file paths to UnmaskedPath entries for the SRT command spec.
 * Default to read-only access to prevent write escalation.
 */
export function maskedPathsToUnmasked(paths: string[], writable = false): UnmaskedPath[] {
  return paths.map((path) => ({ path, writable }));
}