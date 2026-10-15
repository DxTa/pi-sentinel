import { homedir } from "node:os";
import { join } from "node:path";

import { isReadOnlyBashChain } from "./bash-command-safety";
import { extractTokensForPathRules } from "./handlers/gates/bash-path-extractor";
import { getPathPolicyCandidates, isPathWithinDirectory } from "./path-utils";

/** Credential directories whose reads are allowed but always fully redacted. */
function protectedCredentialDirs(): string[] {
  return [join(homedir(), ".ssh"), join(homedir(), ".config")];
}

export function isProtectedCredentialReadPath(pathValue: string, cwd: string): boolean {
  const dirs = protectedCredentialDirs();
  return getPathPolicyCandidates(pathValue, cwd).some((candidate) =>
    dirs.some((dir) => isPathWithinDirectory(candidate, dir)));
}

/**
 * Protected paths read by a read-only Bash chain, or [] when the command also
 * touches any other path or is not provably read-only. Caller must redact all output.
 */
export async function protectedBashReadPaths(command: string, cwd: string): Promise<string[]> {
  if (!isReadOnlyBashChain(command, cwd)) return [];
  const tokens = await extractTokensForPathRules(command);
  if (tokens.length === 0 || !tokens.every((token) => isProtectedCredentialReadPath(token, cwd))) return [];
  return [...new Set(tokens)];
}
