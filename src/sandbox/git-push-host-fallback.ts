import { basename, isAbsolute, resolve } from "node:path";

import { bashInnerCommands, bashLiteralWord, bashWords, scanQuotes, splitBashSegments } from "../bash-segments";
import { isGitExecutable, isPlainGitPushWords, matchesGitPushCommand } from "../yolo-mode";
import { detectImplicitAuthAccess } from "./auth-path-detection";

/** Host fallback is narrower than push detection: one direct, fully literal command. */
export function literalGitPushKey(command: string, cwd: string): string | undefined {
  const scan = scanQuotes(command);
  if (!scan || /[\r\n;&|<>()]/.test(scan.masked)) return undefined;
  const words = bashWords(command);
  if (!words?.length || words.some((word) => bashLiteralWord(word) === null)) return undefined;
  const executable = bashLiteralWord(words[0])!;
  if (executable !== "git" && !(isAbsolute(executable) && basename(executable) === "git")) return undefined;
  if (!matchesGitPushCommand(command)) return undefined;
  return JSON.stringify([resolve(cwd), command]);
}

const LOCAL_GIT_VERBS = new Set([
  "add", "branch", "checkout", "commit", "diff", "log", "restore", "show", "stash", "status", "switch", "tag",
]);
const SIGNING_FLAG = /(^|\s)(-[a-zA-Z]*S|--gpg-sign|--sign|-s)(\s|=|$)/;

/** Local: needs no implicit credentials, and any git call is `git <local verb>` with no options or signing. */
async function isLocalSegment(segment: string, repoRoot: string | null): Promise<boolean> {
  if (await detectImplicitAuthAccess(segment, repoRoot)) return false;
  const words = bashWords(segment);
  if (words === null) return !/\bgit\b/.test(segment);
  const normalized = words.map((word) => bashLiteralWord(word) ?? word);
  if (!normalized.some(isGitExecutable)) return true;
  return isGitExecutable(normalized[0] ?? "")
    && LOCAL_GIT_VERBS.has(normalized[1] ?? "")
    && !SIGNING_FLAG.test(segment);
}

/**
 * Unsandboxed host credentials are allowed for a plain git push only: `git push` or
 * `git -C <path> push`, with no env prefix, wrapper or other global option. Every other
 * segment, from both the inner-command parse and the raw split, must be local. Unparseable
 * or opaque commands keep the block.
 */
export async function implicitAuthIsGitPushOnly(command: string, repoRoot: string | null): Promise<boolean> {
  const parsed = bashInnerCommands(command);
  if (!parsed || parsed.opaque || !matchesGitPushCommand(command)) return false;
  for (const segment of [...parsed.commands, ...(splitBashSegments(command) ?? [])]) {
    const allowed = matchesGitPushCommand(segment)
      ? isPlainGitPushWords(bashWords(segment) ?? [])
      : await isLocalSegment(segment, repoRoot);
    if (!allowed) return false;
  }
  return true;
}
