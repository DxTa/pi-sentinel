import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";

import { extractTokensForPathRules } from "./handlers/gates/bash-path-extractor";
import {
  isPathWithinCanonicalWorkingDirectory,
  isPathWithinDirectory,
  isSensitiveEnvPath,
  isWorkspaceLocalFileOperation,
  resolveReadPathForComparison,
} from "./path-utils";
import { DEFAULT_MASKED_PATTERNS, detectMaskedFileAccess, isPathMasked } from "./sandbox/masked-file-gate";

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

function isWorkspaceDotenvPath(pathValue: string, cwd: string): boolean {
  const canonicalPath = resolveProtectedReadPath(pathValue, cwd);
  return canonicalPath !== null
    && isSensitiveEnvPath(canonicalPath, cwd)
    && isWorkspaceLocalFileOperation("read", { path: canonicalPath }, cwd, { allowWorkspaceEnvRead: true });
}

/** Credential path operands approved read-only by SRT; callers must redact all command output. */
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
  for (const token of [...pathTokens, ...embeddedPaths]) {
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
