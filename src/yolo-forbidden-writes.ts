import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";

import { bashInnerCommands, bashWords, scanQuotes } from "./bash-segments";
import { isForbiddenWritePath } from "./yolo-forbidden-paths";

/* Operands that are written or removed, by verb. */
const ALL_OPERANDS = new Set(["mv", "rm", "rmdir", "unlink", "shred", "touch", "mkdir", "mkfifo", "tee", "truncate", "chmod", "chown", "chgrp"]);
const LAST_OPERAND = new Set(["cp", "ln", "install"]);
const TARGET_DIR_FLAG = /^(?:-t|--target-directory)$/;
const SED_SCRIPT_OPTION = /^(?:-e|-f|--expression|--file)$/;
const SED_ATTACHED_SCRIPT = /^(?:-e.+|-f.+|--expression=.*|--file=.*)$/;
const REDIRECT = /(?:&|\d*)>>?\|?[ \t]*([^\s;|&<>()]+)/g;

const unquote = (word: string): string => word.replace(/^(['"])(.*)\1$/s, "$2");

/* The absolute path a word names, or null when it needs a variable this check cannot expand. */
function resolveWord(word: string, dir: string, home: string): string | null {
  const text = unquote(word).replace(/^(?:\$HOME|\$\{HOME\}|~)(?=\/|$)/, home);
  if (/[$`]/.test(text)) return null;
  return isAbsolute(text) ? text : `${dir}/${text}`;
}

function redirectTargets(text: string): string[] {
  const masked = scanQuotes(text)?.masked;
  if (!masked) return [];
  return [...masked.matchAll(REDIRECT)].map((match) => text.slice(match.index + match[0].length - match[1]!.length, match.index + match[0].length));
}

/* The files of `sed -i`: every operand except the script, which is the first one unless -e/-f gives it. */
function sedFiles(rest: string[]): string[] {
  const files: string[] = [];
  let scripted = false;
  for (let i = 0; i < rest.length; i++) {
    if (SED_SCRIPT_OPTION.test(rest[i]!)) {
      scripted = true;
      i++;
    } else if (SED_ATTACHED_SCRIPT.test(rest[i]!)) scripted = true;
    else if (!rest[i]!.startsWith("-")) files.push(rest[i]!);
  }
  return scripted ? files : files.slice(1);
}

/* Words a writer verb changes: operands, `-t DIR`, `of=`, `-o FILE`, or the files of `sed -i`. */
function writtenWords(words: string[]): string[] {
  const verb = words[0]!.slice(words[0]!.lastIndexOf("/") + 1);
  const rest = words.slice(1);
  const operands = rest.filter((word, i) => !word.startsWith("-") && !TARGET_DIR_FLAG.test(rest[i - 1] ?? ""));
  const targetDirs = rest.flatMap((word, i) =>
    TARGET_DIR_FLAG.test(word) && rest[i + 1] ? [rest[i + 1]!] : word.startsWith("--target-directory=") ? [word.split("=")[1]!] : []);
  if (ALL_OPERANDS.has(verb)) return operands;
  if (LAST_OPERAND.has(verb)) return [...targetDirs, ...operands.slice(-1)];
  if (verb === "dd") return rest.filter((word) => word.startsWith("of=")).map((word) => word.slice(3));
  if (verb === "curl" || verb === "wget") {
    return rest.flatMap((word, i) => /^(?:-o|-O|--output|--output-document)$/.test(word) && rest[i + 1] ? [rest[i + 1]!] : []);
  }
  if (verb === "sed" && rest.some((word) => /^(?:-[a-zA-Z]*i\S*|--in-place\S*)$/.test(word))) return sedFiles(rest);
  return [];
}

const forbiddenAt = (word: string, dir: string, home: string): string | null => {
  const path = resolveWord(word, dir, home);
  return path && isForbiddenWritePath(path, home) ? resolve(path) : null;
};

/* Redirects and writer verbs of each inner command, with `cd` tracked between them. */
function bashWriteTarget(command: string, base: string, home: string): string | null {
  const inner = bashInnerCommands(command);
  let dir = base;
  for (const part of inner?.commands ?? [command]) {
    const words = bashWords(part) ?? [];
    if (words[0] === "cd" && words[1]) dir = resolveWord(words[1], dir, home) ?? dir;
    const targets = [...redirectTargets(part), ...(inner && words.length ? writtenWords(words) : [])];
    for (const target of targets) {
      // A child shell's `cd` may not carry over, so also read relative targets from the start directory.
      const hit = forbiddenAt(target, dir, home) ?? (inner?.scoped ? forbiddenAt(target, base, home) : null);
      if (hit) return hit;
    }
  }
  return null;
}

/**
 * The first forbidden path a write/edit or readable Bash command would change, or
 * null. Best effort: commands the parser cannot read (eval, interpreter code) pass.
 */
export function forbiddenWriteTarget(
  toolName: string,
  input: unknown,
  cwd: string | undefined,
  home: string = homedir(),
): string | null {
  const base = cwd ?? process.cwd();
  const record = (input ?? {}) as Record<string, unknown>;
  if (toolName === "write" || toolName === "edit") {
    return typeof record.path === "string" ? forbiddenAt(record.path, base, home) : null;
  }
  return toolName === "bash" && typeof record.command === "string" ? bashWriteTarget(record.command, base, home) : null;
}
