/**
 * Trusted Pi agent directory (~/.pi/agent, symlinks resolved).
 * Read-only tool calls inside them, and a single command that only runs one
 * script stored in them, are auto-allowed in every permission mode.
 * Writes are never trusted here, so a new script still needs approval first.
 */
import { readdirSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import {
  getPathBearingToolPath,
  isPathWithinDirectory,
  READ_ONLY_PATH_BEARING_TOOLS,
} from "#src/path-utils";

export type TrustedPiMatch = { kind: "read" | "script"; path: string };

const READ_TOOLS = new Set([...READ_ONLY_PATH_BEARING_TOOLS, "ls"]);
const INTERPRETERS = new Set(["bash", "sh", "zsh", "node", "python", "python3"]);
/** Any shell control, redirection, substitution, or expansion disqualifies the command. */
const CHAIN_OPERATOR = new RegExp("&&|;");
const WHITESPACE = new RegExp("\\s+");
const SHELL_SYNTAX = /[<>&|;`$(){}\n]/;

export function trustedPiDirs(agentDir: string): string[] {
  // Exact subagent delegation helper (~/.pi/scripts/delegate-prompt.sh); siblings stay gated.
  const dirs = [agentDir, join(dirname(agentDir), "scripts", "delegate-prompt.sh")];
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

/**
 * Replace quoted arguments with a placeholder so punctuation inside quotes is not
 * mistaken for shell syntax. Double quotes still expand `$`, backticks, and `\`, so
 * those reject; unbalanced quotes reject.
 */
function maskQuotedArguments(command: string): string | null {
  let out = "";
  for (let i = 0; i < command.length; i++) {
    const char = command[i]!;
    if (char !== "'" && char !== '"') {
      out += char;
      continue;
    }
    const end = command.indexOf(char, i + 1);
    if (end === -1) return null;
    if (char === '"' && /[$`\\]/.test(command.slice(i + 1, end))) return null;
    out += "Q";
    i = end;
  }
  return out;
}

/** `cd <dir>` and trusted script runs chained with `&&` or `;`; any other step rejects. */
function matchScript(command: string, cwd: string, dirs: readonly string[]): TrustedPiMatch | null {
  const masked = maskQuotedArguments(command.trim());
  if (!masked) return null;
  let dir = cwd;
  let match: TrustedPiMatch | null = null;
  for (const segment of masked.split(CHAIN_OPERATOR)) {
    const trimmed = segment.trim();
    if (!trimmed || SHELL_SYNTAX.test(trimmed)) return null;
    const tokens = trimmed.split(WHITESPACE);
    if (tokens[0] === "cd") {
      const target = tokens[1];
      if (tokens.length !== 2 || !target || target === "-" || target.startsWith("$")) return null;
      dir = resolve(dir, expandHome(target));
      continue;
    }
    const script = INTERPRETERS.has(basename(tokens[0]!)) ? tokens[1] : tokens[0];
    if (!script || script.startsWith("-")) return null;
    const path = resolve(dir, expandHome(script));
    const real = canonicalWithin(path, dirs);
    if (!real || !statSync(real).isFile()) return null;
    match ??= { kind: "script", path };
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
