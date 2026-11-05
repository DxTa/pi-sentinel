import { closeSync, existsSync, globSync, lstatSync, openSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { extractTokensForPathRules } from "./handlers/gates/bash-path-extractor";
import {
  isPathWithinCanonicalWorkingDirectory,
  isPathWithinDirectory,
  isSensitiveEnvPath,
  isWorkspaceLocalFileOperation,
  resolveReadPathForComparison,
} from "./path-utils";
import { DEFAULT_MASKED_PATTERNS, detectMaskedFileAccess, isPathMasked } from "./sandbox/masked-file-gate";
import { validateSandboxGrantPath } from "./sandbox/settings.js";

function resolveProtectedReadPath(pathValue: string, cwd: string): string | null {
  const expanded = pathValue.replace(/\$\{HOME\}|\$HOME/g, homedir());
  const resolved = resolveReadPathForComparison(expanded, cwd);
  if (!resolved) return null;
  try {
    return existsSync(resolved) ? realpathSync.native(resolved) : resolved;
  } catch {
    return null;
  }
}

/** Credential directories whose reads are allowed but always fully redacted. */
function protectedCredentialDirs(canonicalHome: string): string[] {
  return [join(canonicalHome, ".ssh"), join(canonicalHome, ".config")];
}

export function isProtectedCredentialReadPath(pathValue: string, cwd: string): boolean {
  const canonicalPath = resolveProtectedReadPath(pathValue, cwd);
  if (!canonicalPath) return false;

  if (basename(canonicalPath).toLowerCase() === ".env.example") return false;
  if (
    isSensitiveEnvPath(canonicalPath, cwd)
    && isWorkspaceLocalFileOperation("read", { path: canonicalPath }, cwd, { allowWorkspaceEnvRead: true })
  ) {
    return false;
  }

  let canonicalHome = homedir();
  try {
    canonicalHome = realpathSync.native(canonicalHome);
  } catch {
    return false;
  }
  const withinCredentialScope = isPathWithinCanonicalWorkingDirectory(canonicalPath, cwd)
    || isPathWithinDirectory(canonicalPath, canonicalHome);
  if (!withinCredentialScope) return false;

  const dirs = protectedCredentialDirs(canonicalHome);
  return dirs.some((dir) => isPathWithinDirectory(canonicalPath, dir))
    || isPathMasked(canonicalPath, DEFAULT_MASKED_PATTERNS);
}

/** A target is masked when it matches a pattern or is the root of a masked directory (`dir/**`). */
function isMaskedTargetOrRoot(target: string, patterns: string[]): boolean {
  return isPathMasked(target, patterns) || isPathMasked(join(target, "x"), patterns);
}

/** macOS paths are case-insensitive: match a folded target against folded patterns, with ~ expanded first. */
function isMaskedIgnoringCase(target: string, patterns: string[]): boolean {
  const folded = patterns.map((pattern) =>
    (pattern.startsWith("~/") ? join(homedir(), pattern.slice(2)) : pattern).toLowerCase());
  return isMaskedTargetOrRoot(target.toLowerCase(), folded);
}

/**
 * Why a protected write target cannot be approved as one file, or undefined when it can.
 * SRT strips a trailing `/**` and then grants the whole directory, so globs and directories are refused.
 */
export function protectedWriteRefusal(target: string, maskedPatterns: string[]): string | undefined {
  // SRT trims approved paths, so a spelling with edge whitespace could grant its trimmed, masked twin.
  if (target !== target.trim()) return "has leading or trailing whitespace";
  if (/[*?[\]]/.test(target)) return "contains glob characters";
  if (existsSync(target) && !statSync(target).isFile()) return "is not a regular file";
  if (isMaskedTargetOrRoot(target, maskedPatterns) || isMaskedIgnoringCase(target, maskedPatterns)) return "is masked";
  try {
    validateSandboxGrantPath(target);
  } catch {
    return "is not an allowed grant path";
  }
  return undefined;
}

/**
 * Create an approved target so SRT can write it. SRT denies create on the exact path, so a missing file must exist first.
 * An existing symlink is refused, since lstat does not follow it.
 */
export function prepareApprovedTarget(target: string): string | undefined {
  const dir = dirname(target);
  try {
    // Re-check the parent after approval: a symlink swapped in during the prompt must not redirect the create.
    if (realpathSync.native(dir) !== dir) return "is under a symlinked directory";
    closeSync(openSync(target, "wx", 0o600));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") return "could not be created";
  }
  const stat = lstatSync(target);
  if (!stat.isFile()) return "is not a regular file";
  // A hard link shares content with another path that SRT does not deny by name.
  return stat.nlink > 1 ? "is hard-linked" : undefined;
}

function isWorkspaceDotenvPath(pathValue: string, cwd: string): boolean {
  const canonicalPath = resolveProtectedReadPath(pathValue, cwd);
  return canonicalPath !== null
    && isSensitiveEnvPath(canonicalPath, cwd)
    && isWorkspaceLocalFileOperation("read", { path: canonicalPath }, cwd, { allowWorkspaceEnvRead: true });
}

/** Credential path operands approved read-only by SRT; callers must redact all command output. */
/**
 * Shell glob words expanded against the filesystem. The path-token extractor drops bracket forms such as `[d]`,
 * so the raw words are expanded here. Quotes are stripped: extra matches only add candidates, which are checked the same way.
 */
function expandGlobWords(command: string, cwd: string): string[] {
  const home = homedir();
  return command.split(/[\s;&|()<>]+/)
    .filter((word) => /[*?[]/.test(word))
    .flatMap((word) => {
      const pattern = word
        .replace(/["']/g, "")
        .replace(/\$\{HOME\}|\$HOME/g, home)
        .replace(/^~(?=\/)/, home);
      return globSync(pattern, { cwd }).map((match) => resolve(cwd, match));
    });
}

export async function protectedBashReadPaths(command: string, cwd: string): Promise<string[]> {
  const tokens = await extractTokensForPathRules(command);
  const embeddedMaskedPaths = detectMaskedFileAccess(
    command,
    { maskedPaths: [...DEFAULT_MASKED_PATTERNS, "~/.config/**"] },
    cwd,
    { includeMissing: true },
  );
  const paths = new Set<string>();
  const pathTokens = tokens.filter((token) =>
    !/[`'"]/.test(token) || /^[^`'"]*[\\/]/.test(token),
  );
  const directPaths = new Set(
    pathTokens.map((token) => resolveProtectedReadPath(token, cwd)).filter((path): path is string => path !== null),
  );
  const embeddedPaths = embeddedMaskedPaths.filter((path) =>
    ![...directPaths].some((directPath) => directPath !== path && directPath.startsWith(path)),
  );
  for (const token of [...pathTokens, ...embeddedPaths, ...expandGlobWords(command, cwd)]) {
    const canonicalPath = resolveProtectedReadPath(token, cwd);
    if (
      canonicalPath
      && (isProtectedCredentialReadPath(canonicalPath, cwd) || isWorkspaceDotenvPath(canonicalPath, cwd))
    ) {
      paths.add(canonicalPath);
    }
  }
  return [...paths];
}
