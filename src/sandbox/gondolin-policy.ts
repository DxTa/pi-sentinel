import { lstatSync, realpathSync } from "node:fs";
import { isIP } from "node:net";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";

export const GONDOLIN_PLACEHOLDER_DECISION = "placeholder" as const;

export type GondolinVfsDecision = "allow" | "deny" | "placeholder";
export type GondolinSensitiveReadDecision = "placeholder" | "deny";

export interface GondolinVfsPolicy {
  workspaceRoot: string;
  sensitivePaths?: readonly string[];
  sensitiveReadDecision?: GondolinSensitiveReadDecision;
  /** Host-managed paths may be read but never mutated by VM operations. */
  protectedPaths?: readonly string[];
}

export interface GondolinVfsRequest {
  operation: string;
  path: string;
  /** Host-resolved target, when the VFS has already resolved a symlink. */
  resolvedTargetPath?: string;
}

export interface GondolinVfsDecisionResult {
  decision: GondolinVfsDecision;
  path: string | null;
  reason: string;
}

export interface GondolinNetworkPolicy {
  allowedDomains: readonly string[];
  deniedDomains?: readonly string[];
}

export interface GondolinNetworkRequest {
  protocol: string;
  domain: string;
  /** HTTP methods are intentionally not restricted individually. */
  method?: string;
}

export interface GondolinNetworkDecisionResult {
  decision: "allow" | "deny";
  domain: string | null;
  reason: string;
}

export const DEFAULT_GONDOLIN_SENSITIVE_PATHS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  ".ssh/**",
  ".aws/**",
  ".gnupg/**",
  ".kube/**",
  ".docker/**",
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".git-credentials",
  ".config/git/credentials",
  ".config/gh/hosts.yml",
  ".config/gcloud/**",
  ".config/azure/**",
  ".config/claude/**",
  ".config/codex/**",
  ".config/anthropic/**",
  ".config/openai/**",
  ".config/pip/pip.conf",
  ".cargo/credentials*",
  ".gradle/gradle.properties",
  ".m2/settings*.xml",
  ".local/share/keyrings/**",
  "**/credentials.json",
  "**/credentials.db",
  "**/token.json",
  "**/auth.json",
  "**/auth-token.json",
  "**/secrets.json",
  "**/passwords.json",
  ".pi/agent/auth.json",
] as const;

export const DEFAULT_GONDOLIN_HOME_SENSITIVE_PATHS = [
  ...DEFAULT_GONDOLIN_SENSITIVE_PATHS,
  ".pi",
  ".pi/**",
  ".cache/gondolin",
  ".cache/gondolin/**",
  "Library/Keychains/**",
  "**/*credentials*",
  "**/*token*",
  "**/*secret*",
  "**/*password*",
  "**/*passwd*",
  "**/*auth*",
] as const;

const READ_OPERATION = "read";
const MUTATION_OPERATIONS = new Set(["write", "open", "mkdir", "rmdir", "unlink", "rename"]);
const NUL_BYTE = "\u0000";
const HTTP_PROTOCOLS = new Set(["http", "https"]);

function isWithinRoot(candidate: string, root: string): boolean {
  const relativePath = relative(root, candidate);
  return relativePath === "" || (!relativePath.startsWith(".." + sep) && relativePath !== "..");
}

/**
 * Resolve an existing path's symlinks. For a not-yet-created path, resolve
 * symlinked ancestors so a child cannot escape through a symlink directory.
 */
function resolveHostPath(candidate: string): string | null {
  try {
    return realpathSync.native(candidate);
  } catch {
    const missingParts: string[] = [];
    let current = candidate;
    while (true) {
      try {
        const stats = lstatSync(current);
        if (stats.isSymbolicLink()) {
          try {
            return resolve(realpathSync.native(current), ...missingParts);
          } catch {
            return null;
          }
        }
        if (missingParts.length > 0 && !stats.isDirectory()) return null;
        return resolve(realpathSync.native(current), ...missingParts);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "ENOENT" && code !== "ENOTDIR") return null;
        const parent = dirname(current);
        if (parent === current) return null;
        missingParts.unshift(basename(current));
        current = parent;
      }
    }
  }
}

function resolveWorkspaceRoot(workspaceRoot: string): string | null {
  try {
    return resolveHostPath(resolve(workspaceRoot));
  } catch {
    return null;
  }
}

interface NormalizedGondolinPath {
  root: string;
  lexicalPath: string;
  resolvedPath: string;
}

function normalizeGondolinRequestPath(
  path: string,
  workspaceRoot: string,
): NormalizedGondolinPath | null {
  if (
    typeof path !== "string" ||
    path.trim() === "" ||
    path.includes(NUL_BYTE) ||
    typeof workspaceRoot !== "string" ||
    workspaceRoot.trim() === "" ||
    workspaceRoot.includes(NUL_BYTE)
  ) {
    return null;
  }

  const root = resolveWorkspaceRoot(workspaceRoot);
  if (root === null) return null;

  let rawLexicalPath: string;
  try {
    rawLexicalPath = isAbsolute(path) ? resolve(path) : resolve(root, path);
  } catch {
    return null;
  }

  const resolvedPath = resolveHostPath(rawLexicalPath);
  if (resolvedPath === null || !isWithinRoot(resolvedPath, root)) return null;

  let lexicalPath = rawLexicalPath;
  if (isAbsolute(path)) {
    try {
      lexicalPath = resolve(root, relative(resolve(workspaceRoot), rawLexicalPath));
    } catch {
      return null;
    }
  }
  return { root, lexicalPath, resolvedPath };
}

/**
 * Normalize a VFS path and return null when it is outside the approved root.
 * Relative and absolute paths are accepted; host symlinks are resolved before
 * checking containment.
 */
export function normalizeGondolinPath(path: string, workspaceRoot: string): string | null {
  return normalizeGondolinRequestPath(path, workspaceRoot)?.resolvedPath ?? null;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}

function globToRegExp(pattern: string): RegExp {
  let expression = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*" && pattern[index + 1] === "*") {
      index += 1;
      if (pattern[index + 1] === "/") {
        index += 1;
        expression += "(?:.*/)?";
      } else {
        expression += ".*";
      }
    } else if (character === "*") {
      expression += "[^/]*";
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += escapeRegExp(character);
    }
  }
  return new RegExp(`${expression}$`);
}

function isSensitivePatternWithinRoot(pattern: string, root: string): boolean {
  const containmentProbe = pattern.replaceAll("*", "x").replaceAll("?", "x");
  return isWithinRoot(containmentProbe, root);
}

function normalizeSensitivePattern(
  pattern: string,
  root: string,
  lexicalRoot: string,
): string | null {
  const trimmed = pattern.trim();
  if (!trimmed || trimmed.includes(NUL_BYTE)) return null;

  const isAbsolutePattern = isAbsolute(trimmed);
  const absolutePattern = isAbsolutePattern ? resolve(trimmed) : resolve(root, trimmed);
  if (!isAbsolutePattern) {
    return isSensitivePatternWithinRoot(absolutePattern, root) ? absolutePattern : null;
  }

  const lexicalCandidate = resolve(root, relative(lexicalRoot, absolutePattern));
  if (isSensitivePatternWithinRoot(lexicalCandidate, root)) return lexicalCandidate;
  return isSensitivePatternWithinRoot(absolutePattern, root) ? absolutePattern : null;
}

function normalizeSensitivePatterns(
  patterns: readonly string[],
  root: string,
  workspaceRoot: string,
): string[] | null {
  const lexicalRoot = resolve(workspaceRoot);
  const normalizedPatterns: string[] = [];
  for (const pattern of patterns) {
    const normalizedPattern = normalizeSensitivePattern(pattern, root, lexicalRoot);
    if (normalizedPattern === null) return null;
    normalizedPatterns.push(normalizedPattern);
  }
  return normalizedPatterns;
}

function isSensitivePath(candidate: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => globToRegExp(pattern).test(candidate));
}

/** Return whether an existing workspace path matches configured sensitive rules. */
export function isGondolinSensitivePath(policy: GondolinVfsPolicy, path: string): boolean {
  if (!policy || typeof policy !== "object") return true;
  const requestedPath = normalizeGondolinRequestPath(path, policy.workspaceRoot);
  if (requestedPath === null) return true;
  const sensitivePaths = policy.sensitivePaths === undefined
    ? DEFAULT_GONDOLIN_SENSITIVE_PATHS
    : policy.sensitivePaths;
  if (!Array.isArray(sensitivePaths) || sensitivePaths.some((value) => typeof value !== "string")) return true;
  const normalizedPatterns = normalizeSensitivePatterns(
    sensitivePaths,
    requestedPath.root,
    policy.workspaceRoot,
  );
  if (normalizedPatterns === null) return true;
  return isSensitivePath(requestedPath.lexicalPath, normalizedPatterns) ||
    isSensitivePath(requestedPath.resolvedPath, normalizedPatterns);
}

function denyVfs(path: string | null, reason: string): GondolinVfsDecisionResult {
  return { decision: "deny", path, reason };
}

/** Evaluate a pure, fail-closed VFS decision for a Gondolin request. */
export function decideGondolinVfsAccess(
  policy: GondolinVfsPolicy,
  request: GondolinVfsRequest,
): GondolinVfsDecisionResult {
  if (policy === null || typeof policy !== "object") {
    return denyVfs(null, "Gondolin VFS policy is unavailable.");
  }
  if (request === null || typeof request !== "object") {
    return denyVfs(null, "Gondolin VFS request is invalid.");
  }

  const requestedPath = normalizeGondolinRequestPath(request.path, policy.workspaceRoot);
  if (requestedPath === null) {
    return denyVfs(null, "VFS path is outside the approved workspace root.");
  }
  const normalizedPath = requestedPath.resolvedPath;

  let resolvedTarget = normalizedPath;
  if (request.resolvedTargetPath !== undefined) {
    const targetPath = normalizeGondolinRequestPath(
      request.resolvedTargetPath,
      policy.workspaceRoot,
    );
    if (targetPath === null) {
      return denyVfs(normalizedPath, "VFS symlink target is outside the approved workspace root.");
    }
    resolvedTarget = targetPath.resolvedPath;
  }

  const isRead = request.operation === READ_OPERATION;
  const isMutation = MUTATION_OPERATIONS.has(request.operation);
  if (!isRead && !isMutation) {
    return denyVfs(normalizedPath, "Gondolin VFS policy denies unsupported operations.");
  }

  const root = requestedPath.root;

  const sensitivePaths = policy.sensitivePaths === undefined
    ? DEFAULT_GONDOLIN_SENSITIVE_PATHS
    : policy.sensitivePaths;
  if (
    !Array.isArray(sensitivePaths) ||
    sensitivePaths.some((path) => typeof path !== "string")
  ) {
    return denyVfs(normalizedPath, "Gondolin sensitive-path policy is invalid.");
  }
  const configuredDecision = policy.sensitiveReadDecision;
  if (
    configuredDecision !== undefined &&
    configuredDecision !== "placeholder" &&
    configuredDecision !== "deny"
  ) {
    return denyVfs(normalizedPath, "Gondolin sensitive-read policy is invalid.");
  }
  const normalizedSensitivePatterns = normalizeSensitivePatterns(
    sensitivePaths,
    root,
    policy.workspaceRoot,
  );
  if (normalizedSensitivePatterns === null) {
    return denyVfs(normalizedPath, "Gondolin sensitive-path policy is invalid.");
  }
  const isSensitiveRead =
    isSensitivePath(requestedPath.lexicalPath, normalizedSensitivePatterns) ||
    isSensitivePath(normalizedPath, normalizedSensitivePatterns) ||
    isSensitivePath(resolvedTarget, normalizedSensitivePatterns);
  if (isSensitiveRead) {
    if (isMutation) {
      return denyVfs(normalizedPath, "Gondolin VFS policy denies sensitive mutations.");
    }
    const decision = configuredDecision ?? GONDOLIN_PLACEHOLDER_DECISION;
    return {
      decision,
      path: normalizedPath,
      reason: decision === "placeholder"
        ? "Sensitive VFS read is replaced with the configured placeholder decision."
        : "Sensitive VFS read is denied by policy.",
    };
  }

  const protectedPaths = policy.protectedPaths ?? [];
  if (!Array.isArray(protectedPaths) || protectedPaths.some((path) => typeof path !== "string")) {
    return denyVfs(normalizedPath, "Gondolin protected-path policy is invalid.");
  }
  const normalizedProtectedPatterns = normalizeSensitivePatterns(protectedPaths, root, policy.workspaceRoot);
  if (normalizedProtectedPatterns === null) {
    return denyVfs(normalizedPath, "Gondolin protected-path policy is invalid.");
  }
  const isProtectedMutation = isMutation && (
    isSensitivePath(requestedPath.lexicalPath, normalizedProtectedPatterns) ||
    isSensitivePath(normalizedPath, normalizedProtectedPatterns) ||
    isSensitivePath(resolvedTarget, normalizedProtectedPatterns)
  );
  if (isProtectedMutation) {
    return denyVfs(normalizedPath, "Gondolin VFS policy denies protected-path mutations.");
  }

  return {
    decision: "allow",
    path: normalizedPath,
    reason: isMutation ? "Workspace mutation is allowed." : "Workspace read is allowed.",
  };
}

function normalizeNetworkDomain(value: string): string | null {
  if (typeof value !== "string" || value.trim() === "") return null;
  const input = value.trim().toLowerCase();
  const url = input.includes("://") ? parseNetworkUrl(input) : parseNetworkUrl(`http://${input}`);
  if (url === null) return null;
  const hostname = url.hostname.replace(/\.$/, "");
  if (hostname === "" || hostname.includes("..")) return null;
  const ipHost = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  if (isIP(ipHost) > 0) return hostname;
  const labels = hostname.split(".");
  return labels.every((label) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))
    ? hostname
    : null;
}

function parseNetworkUrl(value: string): URL | null {
  try {
    const url = new URL(value);
    const protocol = url.protocol.slice(0, -1);
    if (!HTTP_PROTOCOLS.has(protocol)) return null;
    if (url.username || url.password || url.hostname === "") return null;
    return url;
  } catch {
    return null;
  }
}

function normalizeDomainPattern(pattern: string): string | null {
  const trimmed = pattern.trim().toLowerCase();
  if (trimmed === "*") return trimmed;
  if (trimmed.startsWith("*.")) {
    const base = normalizeNetworkDomain(trimmed.slice(2));
    return base === null ? null : `*.${base}`;
  }
  return normalizeNetworkDomain(trimmed.replace(/\.$/, ""));
}

function normalizeDomainPatterns(patterns: readonly string[]): string[] | null {
  const normalizedPatterns: string[] = [];
  for (const pattern of patterns) {
    const normalizedPattern = normalizeDomainPattern(pattern);
    if (normalizedPattern === null) return null;
    normalizedPatterns.push(normalizedPattern);
  }
  return normalizedPatterns;
}

function domainMatches(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith(`.${base}`);
  }
  return domain === pattern;
}

/** Normalize a host or URL for deterministic allowlist matching. */
export function normalizeGondolinDomain(domain: string): string | null {
  return normalizeNetworkDomain(domain);
}

/** Evaluate HTTP(S) allowlist access; generic TCP is always denied. */
export function decideGondolinNetworkAccess(
  policy: GondolinNetworkPolicy,
  request: GondolinNetworkRequest,
): GondolinNetworkDecisionResult {
  if (policy === null || typeof policy !== "object") {
    return { decision: "deny", domain: null, reason: "Gondolin network policy is unavailable." };
  }
  if (request === null || typeof request !== "object") {
    return { decision: "deny", domain: null, reason: "Gondolin network request is invalid." };
  }

  const protocol = typeof request.protocol === "string"
    ? request.protocol.trim().toLowerCase()
    : "";
  const domain = normalizeNetworkDomain(request.domain);
  if (!HTTP_PROTOCOLS.has(protocol)) {
    return {
      decision: "deny",
      domain,
      reason: "Gondolin network policy denies generic TCP and unsupported protocols.",
    };
  }
  if (domain === null) {
    return { decision: "deny", domain: null, reason: "Network request has no valid domain." };
  }
  if (
    !Array.isArray(policy.allowedDomains) ||
    policy.allowedDomains.some((pattern) => typeof pattern !== "string")
  ) {
    return { decision: "deny", domain, reason: "Gondolin network policy is invalid." };
  }
  const normalizedPatterns = normalizeDomainPatterns(policy.allowedDomains);
  if (normalizedPatterns === null) {
    return { decision: "deny", domain, reason: "Gondolin network policy is invalid." };
  }
  const deniedDomains = policy.deniedDomains ?? [];
  if (!Array.isArray(deniedDomains) || deniedDomains.some((pattern) => typeof pattern !== "string")) {
    return { decision: "deny", domain, reason: "Gondolin network policy is invalid." };
  }
  const normalizedDeniedPatterns = normalizeDomainPatterns(deniedDomains);
  if (normalizedDeniedPatterns === null) {
    return { decision: "deny", domain, reason: "Gondolin network policy is invalid." };
  }
  if (normalizedDeniedPatterns.some((pattern) => domainMatches(domain, pattern))) {
    return { decision: "deny", domain, reason: "Network domain is explicitly denied." };
  }

  const allowed = normalizedPatterns.some((pattern) => domainMatches(domain, pattern));
  return allowed
    ? { decision: "allow", domain, reason: "HTTP(S) domain is allowlisted." }
    : { decision: "deny", domain, reason: "Network domain is not allowlisted." };
}

export const evaluateGondolinVfsPolicy = decideGondolinVfsAccess;
export const evaluateGondolinNetworkPolicy = decideGondolinNetworkAccess;
export const normalizeWorkspacePath = normalizeGondolinPath;
