/*
 * Quote-aware helpers for Bash permission checks. One scanner so every checker
 * (segment split, read-only check, trusted scripts) agrees on what is quoted.
 */

export interface QuoteScan {
  /* Same length as the input; quoted text (quotes included) replaced by "_". */
  masked: string;
  /* A double-quoted parameter expansion ($VAR, ${...}, $(...)) or backtick. */
  expands: boolean;
  /* A command substitution that runs code: $(...), backticks, <(...), >(...). */
  substitutes: boolean;
}

const EXPANSION_START = new RegExp("[A-Za-z0-9_{(@*#?!$-]");
const UNQUOTED_SUBSTITUTION = new RegExp("[$<>][(]|`");
const CONTROL_OPERATOR = new RegExp("&&|[|][|]|[;|\\n]", "g");

/* Null for unbalanced quotes and ambiguous backslash syntax. */
export function scanQuotes(command: string): QuoteScan | null {
  let masked = "";
  let expands = false;
  let substitutes = false;
  for (let i = 0; i < command.length; i++) {
    const char = command[i]!;
    if (char === "\\") {
      // Escaped unquoted words can disguise command names or write-capable flags.
      return null;
    }
    if (char === "'") {
      const end = command.indexOf("'", i + 1);
      if (end === -1) return null;
      masked += "_".repeat(end - i + 1);
      i = end;
      continue;
    }
    if (char !== '"') {
      masked += char;
      continue;
    }
    let end = i + 1;
    for (; end < command.length && command[end] !== '"'; end++) {
      const inner = command[end]!;
      if (inner === "\\") {
        if (command[end + 1] === "\n") return null;
        end++;
      } else if (inner === "`") {
        expands = substitutes = true;
      } else if (inner === "$" && EXPANSION_START.test(command[end + 1] ?? "")) {
        expands = true;
        if (command[end + 1] === "(") substitutes = true;
      }
    }
    if (end >= command.length) return null;
    masked += "_".repeat(end - i + 1);
    i = end;
  }
  return { masked, expands, substitutes: substitutes || UNQUOTED_SUBSTITUTION.test(masked) };
}

/*
 * Split a Bash command into simple segments on unquoted control operators
 * (&&, ||, ;, |, newline). Null for command/process substitution or unbalanced
 * quotes, whose inner commands cannot be matched by prefix rules.
 */
export function splitBashSegments(command: string): string[] | null {
  const scan = scanQuotes(command);
  if (!scan || scan.substitutes || /(^|[^&])&([^&]|$)/.test(scan.masked)) return null;
  const segments: string[] = [];
  let start = 0;
  for (const match of scan.masked.matchAll(CONTROL_OPERATOR)) {
    segments.push(command.slice(start, match.index));
    start = match.index + match[0].length;
  }
  segments.push(command.slice(start));
  return segments.map((segment) => segment.trim()).filter(Boolean);
}
