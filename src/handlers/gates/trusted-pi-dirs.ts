/**
 * Trusted Pi agent directory (~/.pi/agent, symlinks resolved).
 * Read-only tool calls inside them, and a single command that only runs one
 * script stored in them, are auto-allowed in every permission mode.
 * Writes are never trusted here, so a new script still needs approval first.
 */
import { readdirSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { scanQuotes, splitBashSegments } from "#src/bash-segments";
import {
  getPathBearingToolPath,
  isPathWithinDirectory,
  READ_ONLY_PATH_BEARING_TOOLS,
} from "#src/path-utils";

export type TrustedPiMatch = { kind: "read" | "script"; path: string };

const READ_TOOLS = new Set([...READ_ONLY_PATH_BEARING_TOOLS, "ls"]);
const INTERPRETERS = new Set(["bash", "sh", "zsh", "node", "python", "python3"]);
/** Any shell control, redirection, substitution, or expansion disqualifies the command. */
const SHELL_SYNTAX = /[<>&|;`$(){}\n]/;

export function trustedPiDirs(agentDir: string): string[] {
  // Both Pi-owned roots are trusted; writes still use normal permission gates.
  const dirs = [agentDir, join(dirname(agentDir), "scripts")];
  // Top-level symlinked dirs (e.g. linked skill dirs) are part of the agent tree, but a
  // link to an ancestor of the agent dir (home or filesystem root) would trust far too much.
  try {
    const realAgentDir = realpathSync.native(agentDir);
    for (const entry of readdirSync(agentDir, { withFileTypes: true })) {
      if (!entry.isSymbolicLink()) continue;
      try {
        const target = realpathSync.native(join(agentDir, entry.name));
        if (statSync(target).isDirectory() && !isPathWithinDirectory(realAgentDir, target)) dirs.push(target);
      } catch {
        // Broken link: nothing to trust.
      }
    }
  } catch {
    // Missing agent dir: only the static entries apply.
  }
  return dirs;
}

function expandHome(path: string): string {
  return path === "~" || path.startsWith("~/") ? join(homedir(), path.slice(1)) : path;
}

/** Canonical path when it resolves (symlinks followed) inside a trusted dir. */
function canonicalWithin(path: string, dirs: readonly string[]): string | null {
  try {
    const real = realpathSync.native(path);
    for (const dir of dirs) {
      try {
        if (isPathWithinDirectory(real, realpathSync.native(dir))) return real;
      } catch {
        // Missing trusted dir: nothing can be inside it.
      }
    }
  } catch {
    // Missing target: not trusted.
  }
  return null;
}

/** `cd <dir>` and trusted script runs chained with `&&` or `;`; any other step rejects. */
type ScriptStep =
  | { kind: "cd"; path: string }
  | { kind: "script"; path: string };

/** Parse and validate one segment of a trusted Pi command chain. */
function matchScriptSegment(segment: string, dir: string, dirs: readonly string[]): ScriptStep | null {
  const scan = scanQuotes(segment);
  if (!scan) return null;
  const words = [...scan.masked.matchAll(/\S+/g)];
  const tokens = words.map((word) => segment.slice(word.index, word.index + word[0].length));
  const operandIndex = tokens[0] === "cd" || INTERPRETERS.has(basename(tokens[0] ?? "")) ? 1 : 0;
  const operand = tokens[operandIndex];
  if (!operand) return null;
  let script = operand;
  const singleQuoted = script.startsWith("'");
  const quoted = (script.startsWith('"') && script.endsWith('"'))
    || (singleQuoted && script.endsWith("'"));
  if (quoted) script = script.slice(1, -1);
  // HOME expansion is safe only inside double quotes; unquoted values undergo field splitting.
  if (quoted && !singleQuoted) {
    if (script.startsWith("$HOME/")) script = join(homedir(), script.slice(6));
    else if (script.startsWith("${HOME}/")) script = join(homedir(), script.slice(8));
  }
  if (/["'$`\\*?{}]/.test(script) || script.startsWith("-")) return null;
  const operandWord = words[operandIndex]!;
  const rest = segment.slice(0, operandWord.index) + "SCRIPT" + segment.slice(operandWord.index + operandWord[0].length);
  const restScan = scanQuotes(rest);
  if (!restScan || restScan.expands || restScan.substitutes || SHELL_SYNTAX.test(restScan.masked) || rest.includes(String.fromCharCode(92))) return null;
  const path = resolve(dir, quoted ? script : expandHome(script));
  if (tokens[0] === "cd") {
    return tokens.length === 2 ? { kind: "cd", path } : null;
  }
  const real = canonicalWithin(path, dirs);
  if (!real || !statSync(real).isFile()) return null;
  return { kind: "script", path };
}

/** `cd <dir>` and trusted script runs chained with `&&` or `;`; any other step rejects. */
function matchScript(command: string, cwd: string, dirs: readonly string[]): TrustedPiMatch | null {
  const segments = splitBashSegments(command.trim());
  const fullScan = scanQuotes(command);
  if (!segments || !fullScan || /[|<>\n\r]/.test(fullScan.masked)) return null;
  let dir = cwd;
  let match: TrustedPiMatch | null = null;
  for (const segment of segments) {
    const step = matchScriptSegment(segment, dir, dirs);
    if (!step) return null;
    if (step.kind === "cd") {
      dir = step.path;
      continue;
    }
    match ??= step;
  }
  return match;
}

export function matchTrustedPiRequest(
  toolName: string,
  input: unknown,
  cwd: string,
  dirs: readonly string[],
): TrustedPiMatch | null {
  if (toolName === "bash") {
    const command = (input as { command?: unknown } | null)?.command;
    return typeof command === "string" ? matchScript(command, cwd, dirs) : null;
  }
  if (!READ_TOOLS.has(toolName)) return null;
  const raw = getPathBearingToolPath(toolName, input);
  if (!raw) return null;
  const path = resolve(cwd, expandHome(raw));
  return canonicalWithin(path, dirs) ? { kind: "read", path } : null;
}
