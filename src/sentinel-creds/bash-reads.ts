/**
 * Bash read-target extraction — detect commands that read file content.
 */
import { readdir } from "node:fs/promises";
import { resolve, basename, dirname, join } from "node:path";
import { homedir } from "node:os";

const MAX_EXPANDED_PATHS = 100;

function stripQuotes(s: string): string {
  return s.replace(/"[^"]*"/g, " ").replace(/'[^']*'/g, " ");
}

/**
 * Extract file paths from bash commands that read file content.
 * Handles: cat, head, tail, less, more, grep, rg, sed, awk, source, .,
 * strings, xxd, hexdump, od, base64, file, jq, yq, sort, uniq, wc,
 * diff, dd, node, python, ruby, perl — including quoted paths.
 */
export function extractReadTargets(command: string): string[] {
  const paths: string[] = [];

  // Commands that take a script/filter/pattern first, then files
  const scriptCommands = /\b(?:grep|rg|egrep|fgrep|awk|sed|perl|python3?|ruby|node|jq|yq)\b/g;
  let sm: RegExpExecArray | null;
  while ((sm = scriptCommands.exec(command)) !== null) {
    const tail = command.slice(sm.index + sm[0].length);
    const tokens = stripQuotes(tail).split(/\s+/).filter(Boolean);
    for (const token of tokens) {
      if (/^[|;&]|^(\d?[<>]|>>|<<)/.test(token)) break;
      if (token.startsWith("-")) continue;
      paths.push(token);
    }
  }

  // Commands that take files directly
  const directCommands =
    /\b(?:cat|head|tail|less|more|nl|tac|rev|strings|xxd|hexdump|od|base64|file|sort|uniq|wc|diff|comm|join|cut|paste|column|source)\b/g;
  let dm: RegExpExecArray | null;
  while ((dm = directCommands.exec(command)) !== null) {
    const tail = command.slice(dm.index + dm[0].length);
    const tokens = stripQuotes(tail).split(/\s+/).filter(Boolean);
    for (const token of tokens) {
      if (/^[|;&]|^(\d?[<>]|>>|<<)/.test(token)) break;
      if (token.startsWith("-")) continue;
      paths.push(token);
    }
  }

  // Shell source / dot operator
  const sourceMatch = /(?:^|\s)(?:source|\.)\s+(\S+)/g;
  let srcm: RegExpExecArray | null;
  while ((srcm = sourceMatch.exec(command)) !== null) {
    paths.push(srcm[1]);
  }

  // Redirect input: cmd < file
  const redirectInput = /<\s*(\S+)/g;
  let rdm: RegExpExecArray | null;
  while ((rdm = redirectInput.exec(command)) !== null) {
    paths.push(rdm[1]);
  }

  // dd if=...
  const ddMatch = /\bif\s*=\s*(\S+)/g;
  let ddm: RegExpExecArray | null;
  while ((ddm = ddMatch.exec(command)) !== null) {
    paths.push(ddm[1]);
  }

  return [...new Set(paths)];
}

/**
 * Expand ~, $HOME, and environment variables in paths.
 */
function expandPathTilde(rawPath: string): string {
  return rawPath
    .replace(/^~(?=\/|$)/, homedir())
    .replace(/\$HOME(?=[\/\s"']|$)/g, homedir());
}

/**
 * Expand glob patterns in file paths. Returns resolved absolute paths.
 */
export async function expandPaths(cwd: string, rawTarget: string): Promise<string[]> {
  const expandedTarget = expandPathTilde(rawTarget);
  const absolutePath = resolve(cwd, expandedTarget);
  const base = basename(absolutePath);
  const dir = dirname(absolutePath);

  if (!base.includes("*") && !base.includes("?")) {
    return [absolutePath];
  }

  try {
    const entries = await readdir(dir);
    const regex = new RegExp(
      "^" + base.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$",
    );
    const matches = entries.filter((f) => regex.test(f));
    if (matches.length === 0) return [absolutePath];
    return matches.slice(0, MAX_EXPANDED_PATHS).map((f) => join(dir, f));
  } catch {
    return [absolutePath];
  }
}
