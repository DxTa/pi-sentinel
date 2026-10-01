/**
 * Trusted Pi agent directory (~/.pi/agent, symlinks resolved).
 * Read-only tool calls inside them, and a single command that only runs one
 * script stored in them, are auto-allowed in every permission mode.
 * Writes are never trusted here, so a new script still needs approval first.
 */
import { realpathSync, statSync } from "node:fs";
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
const SHELL_SYNTAX = /[<>&|;`$(){}\n]/;

export function trustedPiDirs(agentDir: string): string[] {
  // Exact subagent delegation helper (~/.pi/scripts/delegate-prompt.sh); siblings stay gated.
  return [agentDir, join(dirname(agentDir), "scripts", "delegate-prompt.sh")];
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

function matchScript(command: string, cwd: string, dirs: readonly string[]): TrustedPiMatch | null {
  const trimmed = maskQuotedArguments(command.trim());
  if (!trimmed || SHELL_SYNTAX.test(trimmed)) return null;
  const tokens = trimmed.split(/\s+/);
  const script = INTERPRETERS.has(basename(tokens[0]!)) ? tokens[1] : tokens[0];
  if (!script || script.startsWith("-")) return null;
  const path = resolve(cwd, expandHome(script));
  const real = canonicalWithin(path, dirs);
  if (!real || !statSync(real).isFile()) return null;
  return { kind: "script", path };
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
