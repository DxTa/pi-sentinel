import { resolve } from "node:path";

import { scanQuotes, splitBashSegments } from "./bash-segments";
import { isPathWithinCanonicalWorkingDirectory } from "./path-utils";

const SHELL_SYNTAX = /&&|\|\||[;|<>`$]|[\r\n]/;
const READ_ONLY_COMMANDS = new Set([
  "cat", "head", "tail", "grep", "rg", "ag", "wc", "sort", "uniq",
  "diff", "ls", "find", "stat", "du", "df", "echo", "printf", "pwd",
]);
const QUOTE_CHARS = new RegExp("['\"]", "g");
/** Per-command options that write files or run other programs. */
const FORBIDDEN_ARGS: Record<string, RegExp> = {
  find: /^(?:-L|-H|-follow|-(?:exec(?:dir)?|ok(?:dir)?|delete|fprint0?|fprintf|fls))$/,
  sort: /^(?:-o|--output(?:=|$)|--compress-program(?:=|$))/,
  diff: /^--output(?:=|$)/,
  rg: /^--(?:pre|hostname-bin)(?:=|$)/,
};
const SAFE_INSPECT_FIELDS = new Set(["{{.State.Status}}", "{{.State.Running}}", "{{.Config.Image}}"]);

/** True only for one simple command with no known write-capable option. */
export function isReadOnlyBashCommand(command: string): boolean {
  const trimmed = command.trim();
  const scan = scanQuotes(trimmed);
  if (!trimmed || !scan || scan.expands || SHELL_SYNTAX.test(scan.masked)) return false;
  if (FIXED_READ_ONLY_COMMAND.test(trimmed)) return true;

  const [name, ...quotedArgs] = trimmed.split(/\s+/);
  const args = quotedArgs.map((arg) => arg.replace(QUOTE_CHARS, ""));
  if (!READ_ONLY_COMMANDS.has(name ?? "")) return false;
  if (name !== "find" && ["*", "?", "["].some((char) => scan.masked.includes(char))) return false;
  return !args.some((arg) => FORBIDDEN_ARGS[name!]?.test(arg));
}

/** Curated diagnostics safe to allow without repeated approval; no arbitrary inspect output. */
export function isReadOnlyBashDiagnostic(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || SHELL_SYNTAX.test(trimmed)) return false;
  if (/^(?:orb|orbctl|docker) --help$/.test(trimmed)) return true;
  if (/^docker ps$/.test(trimmed)) return true;
  if (/^docker port [A-Za-z0-9][A-Za-z0-9_.-]*(?: \d{1,5}(?:\/(?:tcp|udp))?)?$/.test(trimmed)) return true;
  if (/^ipconfig getifaddr en\d+$/.test(trimmed)) return true;

  const inspect = trimmed.match(/^docker inspect --format (['"])(.+)\1 ([A-Za-z0-9][A-Za-z0-9_.-]*)$/);
  return Boolean(inspect && SAFE_INSPECT_FIELDS.has(inspect[2] ?? ""));
}

const DISCARD_REDIRECT = /\s*(?:[12]?>\s*\/dev\/null|2>&1)(?=\s|$|;|&|\|)/g;
const GIT_READ = /^git (?:status|log|diff|show)(?:\s|$)/;
const SED_PRINT = /^sed -n '?\d+(?:,\d+)?p'? [^\s;&|<>]+$/;
const READ_ONLY_SED_SUBSTITUTION = /^sed\s+(['"])s\/[^/\\'"]*\/[^/\\'"]*\/[0-9gIp]*\1(?:\s+[^-;\s<>|&][^;\s<>|&]*)?$/;
const FIXED_READ_ONLY_COMMAND = new RegExp(`^docker ps$|${READ_ONLY_SED_SUBSTITUTION.source}`);

/**
 * True for a chain of read-only commands joined by &&, ;, or pipes, where every
 * `cd` stays inside cwd and the only redirects discard output. Path operands are
 * checked separately by the workspace-local gate before this is consulted.
 */
export function isReadOnlyBashChain(command: string, cwd: string): boolean {
  const segments = splitBashSegments(command.replace(DISCARD_REDIRECT, ""));
  if (!segments?.length) return false;
  let dir = cwd;
  return segments.every((segment) => {
    const cd = segment.match(/^cd\s+([^\s~$-][^\s$]*)$/);
    if (cd) {
      dir = resolve(dir, cd[1]!);
      return isPathWithinCanonicalWorkingDirectory(dir, cwd);
    }
    if (GIT_READ.test(segment)) return !/[<>`$]|--output|--ext-diff|--textconv/.test(segment);
    return SED_PRINT.test(segment) || isReadOnlyBashCommand(segment);
  });
}
