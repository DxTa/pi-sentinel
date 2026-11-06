import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { basename, dirname, join, normalize, resolve, sep } from "node:path";

import { toRecord } from "./common";
import { expandHomePath } from "./expand-home";
import { wildcardMatch } from "./wildcard-matcher";

const UNICODE_PATH_SPACES = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;
const INVALID_FILE_URL_PATH = "\u0000invalid-file-url/.env";

function normalizeWindowsShellPath(filePath: string): string {
  if (!filePath.startsWith("/") || filePath.startsWith("//") || filePath.includes("\\")) {
    return filePath;
  }
  const match = filePath.match(/^\/(?:mnt\/|cygdrive\/)?([a-z])(?:\/(.*))?$/i);
  if (!match) return filePath;
  const suffix = match[2]?.replaceAll("/", "\\");
  return `${match[1]!.toUpperCase()}:\\${suffix ?? ""}`;
}

export function normalizePathForComparison(pathValue: string, cwd: string): string {
  let normalizedPath = pathValue.replace(UNICODE_PATH_SPACES, " ");
  if (normalizedPath.startsWith("@")) normalizedPath = normalizedPath.slice(1);

  if (process.platform === "win32") {
    normalizedPath = normalizeWindowsShellPath(normalizedPath);
  }

  if (normalizedPath === "~") {
    normalizedPath = homedir();
  } else if (normalizedPath.startsWith("~/") || normalizedPath.startsWith("~\\")) {
    normalizedPath = join(homedir(), normalizedPath.slice(2));
  }

  if (/^file:\/\//.test(normalizedPath)) {
    try {
      normalizedPath = fileURLToPath(normalizedPath);
    } catch {
      return INVALID_FILE_URL_PATH;
    }
  }

  const absolutePath = normalize(resolve(cwd, normalizedPath));
  return process.platform === "win32" ? absolutePath.toLowerCase() : absolutePath;
}

export function isPathWithinDirectory(
  pathValue: string,
  directory: string,
): boolean {
  if (!pathValue || !directory) {
    return false;
  }

  if (pathValue === directory) {
    return true;
  }

  const prefix = directory.endsWith(sep) ? directory : `${directory}${sep}`;
  return pathValue.startsWith(prefix);
}

/**
 * Paths that are universally safe and should never trigger external-directory checks.
 * These are OS device files: read returns EOF or process streams, write discards or goes to process streams.
 */
export const SAFE_SYSTEM_PATHS: ReadonlySet<string> = new Set([
  "/dev/null",
  "/dev/stdin",
  "/dev/stdout",
  "/dev/stderr",
]);

/**
 * Returns true if the given normalized path is a safe OS device file
 * that should never trigger external-directory checks.
 */
export function isSafeSystemPath(normalizedPath: string): boolean {
  return SAFE_SYSTEM_PATHS.has(normalizedPath);
}

/**
 * File tools that only read — never write — the filesystem.
 * Only these tools are eligible for the Pi infrastructure auto-allow.
 */
export const READ_ONLY_PATH_BEARING_TOOLS: ReadonlySet<string> = new Set([
  "read",
  "find",
  "grep",
  "ls",
]);

export const PATH_BEARING_TOOLS = new Set([
  "read",
  "write",
  "edit",
  "find",
  "grep",
  "ls",
]);

export function getPathBearingToolPath(
  toolName: string,
  input: unknown,
): string | null {
  if (!PATH_BEARING_TOOLS.has(toolName)) {
    return null;
  }

  const pathValue = toRecord(input).path;
  return typeof pathValue === "string" && pathValue.trim() !== "" ? pathValue : null;
}

/** Match `.env*` filenames, excluding `.env.example` templates. */
function isSensitiveEnvBasename(pathValue: string): boolean {
  const fileName = basename(pathValue).toLowerCase();
  return fileName.startsWith(".env") && !fileName.endsWith(".env.example");
}

function lowercasePathBasename(pathValue: string): string {
  const trailingSeparators = pathValue.match(/[\\/]+$/)?.[0] ?? "";
  const pathWithoutTrailingSeparators = trailingSeparators
    ? pathValue.slice(0, -trailingSeparators.length)
    : pathValue;
  const separatorIndex = Math.max(
    pathWithoutTrailingSeparators.lastIndexOf("/"),
    pathWithoutTrailingSeparators.lastIndexOf("\\"),
  );
  return `${pathWithoutTrailingSeparators.slice(0, separatorIndex + 1)}${pathWithoutTrailingSeparators.slice(separatorIndex + 1).toLowerCase()}${trailingSeparators}`;
}

/** Resolve the exact read-path spelling Pi will use, including its file-name fallbacks. */
export function resolveReadPathForComparison(pathValue: string, cwd: string): string {
  const resolved = normalizePathForComparison(pathValue, cwd);
  if (resolved === INVALID_FILE_URL_PATH || existsSync(resolved)) return resolved;

  const nfdVariant = resolved.normalize("NFD");
  const variants = [
    resolved.replace(/ (AM|PM)\./gi, "\u202F$1."),
    nfdVariant,
    resolved.replace(/'/g, "\u2019"),
    nfdVariant.replace(/'/g, "\u2019"),
  ];
  return variants.find((candidate) => candidate !== resolved && existsSync(candidate)) ?? resolved;
}

/** Input, normalized, resolved-read, and real paths in both original and case-folded basename forms. */
export function getPathPolicyCandidates(pathValue: string, cwd: string): string[] {
  const normalizedPath = normalizePathForComparison(pathValue, cwd);
  const resolvedReadPath = resolveReadPathForComparison(pathValue, cwd);
  const candidates = [pathValue, normalizedPath, resolvedReadPath];
  for (const candidate of new Set([normalizedPath, resolvedReadPath])) {
    if (!candidate || candidate === INVALID_FILE_URL_PATH) continue;
    try {
      candidates.push(realpathSync.native(candidate));
    } catch {
      // Keep lexical candidates for missing paths and inaccessible targets.
    }
  }
  const uniqueCandidates = [...new Set(candidates.filter(Boolean))];
  const caseFoldedSensitivePaths = uniqueCandidates.some(isSensitiveEnvBasename)
    ? uniqueCandidates.map((candidate) => candidate.toLowerCase())
    : [];
  return [...new Set([
    ...uniqueCandidates,
    ...uniqueCandidates.map(lowercasePathBasename),
    ...caseFoldedSensitivePaths,
  ])];
}

/** Return a case-normalized path for matching the existing `.env*` path rules. */
export function sensitiveEnvPathForPolicy(
  pathValue: string,
  cwd = process.cwd(),
): string | null {
  const candidate = getPathPolicyCandidates(pathValue, cwd).find(isSensitiveEnvBasename);
  return candidate ? lowercasePathBasename(candidate) : null;
}

export function isSensitiveEnvPath(pathValue: string, cwd = process.cwd()): boolean {
  return getPathPolicyCandidates(pathValue, cwd).some(isSensitiveEnvBasename);
}

/**
 * Returns true when a file tool operates within the canonical session workspace.
 * Missing paths are checked through their nearest existing parent so new writes
 * remain eligible without weakening symlink containment.
 */
export interface WorkspaceLocalFileOperationOptions {
  allowWorkspaceEnvRead?: boolean;
  /** Treat a grep/find/ls with a dotenv selector as workspace-local; the caller redacts its output. */
  allowEnvSelector?: boolean;
}

export function hasProtectedEnvSelector(toolName: string, input: unknown): boolean {
  if (toolName !== "grep" && toolName !== "find" && toolName !== "ls") return false;

  const record = toRecord(input);
  return [record.path, record.glob, record.pattern].some((value) =>
    typeof value === "string" && value.toLowerCase().replaceAll("%2e", ".").includes(".env"),
  );
}

export function isWorkspaceLocalFileOperation(
  toolName: string,
  input: unknown,
  cwd: string,
  options: WorkspaceLocalFileOperationOptions = {},
): boolean {
  if (!PATH_BEARING_TOOLS.has(toolName) || !cwd) return false;

  if (hasProtectedEnvSelector(toolName, input) && options.allowEnvSelector !== true) return false;

  const inputPath = getPathBearingToolPath(toolName, input);
  const pathValue = inputPath ?? (
    toolName === "find" || toolName === "grep" || toolName === "ls" ? cwd : null
  );
  if (!pathValue) return false;

  const lexicalPath = normalizePathForComparison(pathValue, cwd);
  const normalizedPath = toolName === "read"
    ? resolveReadPathForComparison(pathValue, cwd)
    : lexicalPath;
  const normalizedCwd = normalizePathForComparison(cwd, cwd);
  if (!normalizedPath || !normalizedCwd || !existsSync(normalizedCwd)) return false;

  const isRequestedEnvPath = isSensitiveEnvBasename(lexicalPath) || isSensitiveEnvBasename(normalizedPath);
  if (toolName === "edit" && !existsSync(normalizedPath)) return false;

  try {
    const canonicalCwd = realpathSync.native(normalizedCwd);
    const canonicalTargetPath = existsSync(normalizedPath)
      ? realpathSync.native(normalizedPath)
      : normalizedPath;
    const isCanonicalEnvTarget = isSensitiveEnvBasename(canonicalTargetPath);
    let candidate = normalizedPath;
    while (!existsSync(candidate)) {
      const parent = dirname(candidate);
      if (parent === candidate) return false;
      candidate = parent;
    }
    const isCanonicalWorkspacePath = isPathWithinDirectory(
      realpathSync.native(candidate),
      canonicalCwd,
    );
    const isAllowedEnvRead = toolName === "read"
      && options.allowWorkspaceEnvRead === true
      && isCanonicalEnvTarget;
    return isCanonicalWorkspacePath
      && (!(isRequestedEnvPath || isCanonicalEnvTarget) || isAllowedEnvRead);
  } catch {
    return false;
  }
}

/**
 * Check workspace locality using canonical filesystem targets.
 * Missing targets are checked through their nearest existing parent so new
 * paths inherit canonical containment; unresolvable targets fail closed.
 */
export function isPathWithinCanonicalWorkingDirectory(
  pathValue: string,
  cwd: string,
): boolean {
  const normalizedPath = resolveReadPathForComparison(pathValue, cwd);
  const normalizedCwd = normalizePathForComparison(cwd, cwd);
  if (!normalizedPath || !normalizedCwd || !existsSync(normalizedCwd)) return false;
  try {
    const canonicalCwd = realpathSync.native(normalizedCwd);
    let candidate = normalizedPath;
    while (!existsSync(candidate)) {
      const parent = dirname(candidate);
      if (parent === candidate) return false;
      candidate = parent;
    }
    return isPathWithinDirectory(realpathSync.native(candidate), canonicalCwd);
  } catch {
    return false;
  }
}

export function isPathOutsideWorkingDirectory(
  pathValue: string,
  cwd: string,
): boolean {
  const normalizedCwd = normalizePathForComparison(cwd, cwd);
  const normalizedPath = resolveReadPathForComparison(pathValue, cwd);
  if (!normalizedCwd || !normalizedPath) {
    return false;
  }
  if (isSafeSystemPath(normalizedPath)) {
    return false;
  }
  return !isPathWithinDirectory(normalizedPath, normalizedCwd);
}

function containsGlobChars(value: string): boolean {
  return value.includes("*") || value.includes("?");
}

/**
 * Returns true if the given tool + normalized path combination qualifies for
 * automatic allow as a Pi infrastructure read.
 *
 * A path qualifies when:
 * 1. The tool is read-only (in READ_ONLY_PATH_BEARING_TOOLS).
 * 2. The normalized path is within one of the provided `infrastructureDirs`
 *    OR within the project-local Pi package directories
 *    (`<cwd>/.pi/npm/` or `<cwd>/.pi/git/`).
 *
 * `infrastructureDirs` entries may be absolute paths or patterns containing
 * `~`/`$HOME` (expanded at call time) or glob characters (`*`, `?`).
 * Project-local paths are computed fresh from `cwd` on each call so they
 * follow working-directory changes without a runtime rebuild.
 */
export function isPiInfrastructureRead(
  toolName: string,
  normalizedPath: string,
  infrastructureDirs: readonly string[],
  cwd: string,
): boolean {
  if (!READ_ONLY_PATH_BEARING_TOOLS.has(toolName)) {
    return false;
  }

  for (const dir of infrastructureDirs) {
    if (containsGlobChars(dir)) {
      if (wildcardMatch(dir, normalizedPath)) return true;
    } else {
      if (isPathWithinDirectory(normalizedPath, expandHomePath(dir)))
        return true;
    }
  }

  // Project-local Pi packages — checked fresh every call so CWD changes work.
  const projectNpmDir = join(cwd, ".pi", "npm");
  const projectGitDir = join(cwd, ".pi", "git");
  if (isPathWithinDirectory(normalizedPath, projectNpmDir)) {
    return true;
  }
  if (isPathWithinDirectory(normalizedPath, projectGitDir)) {
    return true;
  }

  return false;
}
