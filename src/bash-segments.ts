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
const CONTROL_OPERATOR = new RegExp("&&|[|][|]|[|]&|(?<!>)[|]|[;\\n]", "g");

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
  if (!scan || scan.substitutes || /(^|[^&<>|])&(?![&>])/.test(scan.masked)) return null;
  const segments: string[] = [];
  let start = 0;
  for (const match of scan.masked.matchAll(CONTROL_OPERATOR)) {
    segments.push(command.slice(start, match.index));
    start = match.index + match[0].length;
  }
  segments.push(command.slice(start));
  return segments.map((segment) => segment.trim()).filter(Boolean);
}

export interface InnerCommands {
  /* The commands that really run, with shell syntax and transparent wrappers removed. */
  commands: string[];
  /* Code that cannot be read statically (eval, interpreter -c, $cmd...). */
  opaque: boolean;
  /* Runs as another user (sudo). */
  elevated: boolean;
  /* Some commands run in a child shell, so a `cd` there does not change the parent directory. */
  scoped: boolean;
}

interface Word {
  text: string;
  start: number;
}

const LEADING_KEYWORDS = new Set(["if", "then", "elif", "else", "while", "until", "do", "!", "{"]);
const CLOSING_KEYWORDS = new Set(["done", "fi", "esac", "}"]);
const LOOP_HEADERS = new Set(["for", "select"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const NO_OPTIONS = { valued: /(?!)/, plain: /(?!)/ };
const WRAPPERS: Record<string, { valued: RegExp; plain: RegExp }> = {
  env: { valued: /^-u$/, plain: /^-[i0v]+$/ },
  timeout: { valued: /^-[ks]$/, plain: /^-v$|^--(?:foreground|preserve-status|verbose)$/ },
  nice: { valued: /^-n$/, plain: /^-\d+$|^-n\d+$/ },
  time: { valued: /(?!)/, plain: /^-p$/ },
  command: { valued: /(?!)/, plain: /^-p$/ },
  nohup: NO_OPTIONS,
  exec: NO_OPTIONS,
  sudo: { valued: /^-[ughpCTrt]$/, plain: /^-[EnHSkKbPAB]+$|^--$/ },
};
const XARGS_OPTIONS = { valued: /^-[nILPsdEa]$/, plain: /^-(?:[0rtpxi]+|[nILPsdEa].+)$/ };
const FIND_EXEC = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
const FIND_TERMINATOR = /^(?:';'|";"|\+)$/;
const SHELL = /^(?:ba|z|da)?sh$/;
const SHELL_CODE_FLAG = /^-[a-zA-Z]*c[a-zA-Z]*$/;
const SHELL_STDIN_FLAG = /^-[a-zA-Z]*s[a-zA-Z]*$/;
const SHELL_VALUED_OPTION = /^[-+][oO]$|^--(?:rcfile|init-file)$/;
const MAX_SHELL_DEPTH = 2;
const OPAQUE_COMMANDS = new Set(["eval", "source", ".", "trap", "case", "function", "builtin"]);
const INTERPRETER = /^(?:python[\d.]*|node(?:js)?|bun|perl|ruby|php)$/;
const INTERPRETER_CODE_FLAG = /^(?:-[a-zA-Z]*[ceEpr][a-zA-Z]*|--eval|--print)$/;
/* Assignments that change which program or code a command runs. */
const SENSITIVE_ASSIGNMENT = /^(?:PATH|IFS|ENV|BASH_ENV|SHELLOPTS|PS4|PROMPT_COMMAND|LD_\w*|DYLD_\w*)=/;
/* A command name that is quoted, built by expansion, or not a name at all cannot be matched by a rule. */
const UNREADABLE_COMMAND_NAME = /[$`'"]|^-|^\d*[<>]/;
const DURATION = /^\d+(?:\.\d+)?[smhd]?$/;

const baseName = (word: string): string => word.slice(word.lastIndexOf("/") + 1);

function wordsOf(text: string, masked: string): Word[] {
  return [...masked.matchAll(/\S+/g)].map((match) => ({ text: text.slice(match.index, match.index + match[0].length), start: match.index }));
}

/* The shell words of one simple command, quotes kept; null for unbalanced quotes. */
export function bashWords(command: string): string[] | null {
  const scan = scanQuotes(command);
  return scan ? wordsOf(command, scan.masked).map((word) => word.text) : null;
}

function redirectionOperatorEnd(masked: string, index: number): number | null {
  if (masked.startsWith("&>", index)) return index + (masked[index + 2] === ">" ? 3 : 2);
  if (masked[index] !== "<" && masked[index] !== ">") return null;
  if (masked.startsWith("<<<", index) || masked.startsWith("<<-", index)) return index + 3;
  if (["<<", ">>", "<>", ">&", "<&", ">|"].some((operator) => masked.startsWith(operator, index))) return index + 2;
  return index + 1;
}

function redirectionStart(masked: string, operatorStart: number): number {
  let descriptorStart = operatorStart;
  while (descriptorStart > 0 && /\d/.test(masked[descriptorStart - 1] ?? "")) descriptorStart--;
  if (
    descriptorStart < operatorStart
    && (descriptorStart === 0 || /[\s;&|()]/.test(masked[descriptorStart - 1]!))
  ) return descriptorStart;

  if (masked[operatorStart - 1] === "}") {
    const namedDescriptorStart = masked.lastIndexOf("{", operatorStart - 1);
    if (
      namedDescriptorStart >= 0
      && /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(masked.slice(namedDescriptorStart, operatorStart))
      && (namedDescriptorStart === 0 || /[\s;&|()]/.test(masked[namedDescriptorStart - 1]!))
    ) return namedDescriptorStart;
  }
  return operatorStart;
}

function redirectionEnd(masked: string, operatorEnd: number): number {
  let targetStart = operatorEnd;
  while (/\s/.test(masked[targetStart] ?? "")) targetStart++;
  const nextIsOperator = targetStart >= masked.length
    || /^(?:&&|\|\||[;|\n])/.test(masked.slice(targetStart))
    || ["<", ">", "&>"].some((operator) => masked.startsWith(operator, targetStart));
  if (nextIsOperator) return operatorEnd;

  let targetEnd = targetStart;
  while (targetEnd < masked.length && !/[\s<>|;&\n]/.test(masked[targetEnd]!)) targetEnd++;
  return targetEnd;
}

/* Shell words with redirection operators and their separate targets removed. */
export function bashWordsWithoutRedirections(command: string): string[] | null {
  const scan = scanQuotes(command);
  if (!scan) return null;
  const masked = scan.masked.split("");

  for (let index = 0; index < masked.length; index++) {
    const operatorEnd = redirectionOperatorEnd(scan.masked, index);
    if (operatorEnd === null) continue;

    const start = redirectionStart(scan.masked, index);
    const end = redirectionEnd(scan.masked, operatorEnd);
    for (let position = start; position < end; position++) masked[position] = " ";
    index = end - 1;
  }

  return wordsOf(command, masked.join("")).map((word) => word.text);
}

/* Index after the wrapper's options, or -1 for an option this table does not know. */
function afterOptions(words: Word[], from: number, wrapper: { valued: RegExp; plain: RegExp }): number {
  let i = from;
  while (i < words.length && words[i]!.text.startsWith("-")) {
    if (wrapper.valued.test(words[i]!.text)) i += 2;
    else if (wrapper.plain.test(words[i]!.text)) i += 1;
    else return -1;
  }
  return i;
}

/* Index after a wrapper and its options, or -1 for an option this table does not know. */
function skipWrapper(words: Word[], at: number, result: InnerCommands): number {
  const name = baseName(words[at]!.text);
  if (name === "sudo") result.elevated = true;
  const next = afterOptions(words, at + 1, WRAPPERS[name]!);
  return next >= 0 && name === "timeout" && DURATION.test(words[next]?.text ?? "") ? next + 1 : next;
}

/* Index of the real command after wrappers, or -1 when a wrapper cannot be read. */
function skipPrefix(words: Word[], result: InnerCommands): number {
  let i = 0;
  while (i < words.length) {
    const word = words[i]!.text;
    if (SENSITIVE_ASSIGNMENT.test(word)) return -1;
    if (LEADING_KEYWORDS.has(word) || ASSIGNMENT.test(word)) i++;
    else if (!WRAPPERS[baseName(word)] || (word === "command" && /^-[vV]$/.test(words[i + 1]?.text ?? ""))) return i;
    else {
      i = skipWrapper(words, i, result);
      if (i < 0) return -1;
    }
  }
  return i;
}

function readLiteralPart(word: string, start: number): { value: string; end: number } | null {
  const quote = word[start];
  if (quote === "'" || quote === '"') {
    const end = word.indexOf(quote, start + 1);
    if (end < 0) return null;
    const value = word.slice(start + 1, end);
    if (quote === '"' && value.includes("\\")) return null;
    return { value, end: end + 1 };
  }

  let end = start;
  while (end < word.length && word[end] !== "'" && word[end] !== '"') {
    if (!/[\w./:=+,@%-]/.test(word[end]!)) return null;
    end++;
  }
  return end === start ? null : { value: word.slice(start, end), end };
}

/* The text of a statically literal shell word; null when expansion or escapes are involved. */
export function bashLiteralWord(word: string | undefined): string | null {
  if (word === undefined) return null;
  const scan = scanQuotes(word);
  if (!scan || scan.expands) return null;

  let value = "";
  for (let index = 0; index < word.length;) {
    const part = readLiteralPart(word, index);
    if (!part) return null;
    value += part.value;
    index = part.end;
  }
  return value;
}

/* Shell words with quoting removed only when each word is statically literal. */
export function bashLiteralWords(command: string): string[] | null {
  const words = bashWordsWithoutRedirections(command);
  if (!words) return null;
  const literals = words.map(bashLiteralWord);
  return literals.every((word): word is string => word !== null) ? literals : null;
}

/* The `-c` code of a shell invocation: a string, null when unreadable or read from stdin, undefined for a script file. */
function shellCode(words: Word[], first: number): string | null | undefined {
  let i = first + 1;
  while (words[i]?.text.startsWith("-") && !SHELL_CODE_FLAG.test(words[i]!.text)) {
    if (SHELL_STDIN_FLAG.test(words[i]!.text)) return null;
    i += SHELL_VALUED_OPTION.test(words[i]!.text) ? 2 : 1;
  }
  const word = words[i]?.text;
  if (word === "<<<") return bashLiteralWord(words[i + 1]?.text);
  if (word === undefined || word.startsWith("<") || /^['"]/.test(word)) return null;
  return SHELL_CODE_FLAG.test(word) ? bashLiteralWord(words[i + 1]?.text) : undefined;
}

function markOpaque(text: string, result: InnerCommands): void {
  result.opaque = true;
  result.commands.push(text);
}

/* Code the shell would run that no rule can match: eval, interpreter code, a dynamic command name. */
function runsUnreadableCode(words: Word[], first: number): boolean {
  const head = words[first]!.text;
  const name = baseName(head);
  return UNREADABLE_COMMAND_NAME.test(head)
    || OPAQUE_COMMANDS.has(name)
    || (INTERPRETER.test(name) && words.slice(first + 1).some((word) => INTERPRETER_CODE_FLAG.test(word.text)));
}

/* The commands of every `-exec` clause; opaque when a clause has no terminator. */
function collectFindExec(words: Word[], result: InnerCommands, depth: number): void {
  words.forEach((word, i) => {
    if (!FIND_EXEC.has(word.text)) return;
    const end = words.findIndex((candidate, j) => j > i && FIND_TERMINATOR.test(candidate.text));
    if (end < 0) result.opaque = true;
    else {
      result.scoped = true;
      collectSegment(words.slice(i + 1, end).map((w) => w.text).join(" "), result, depth);
    }
  });
}

/* The commands of `bash -c '<code>'`, up to two levels deep; opaque past that or when the code cannot be split. */
function collectShellCode(code: string, text: string, result: InnerCommands, depth: number): void {
  const inner = depth < MAX_SHELL_DEPTH ? splitBashSegments(code) : null;
  if (!inner) return markOpaque(text, result);
  result.scoped = true;
  for (const part of inner) collectSegment(part, result, depth + 1);
}

function collectSegment(segment: string, result: InnerCommands, depth = 0): void {
  if (/^\s*\(/.test(segment)) result.scoped = true;
  const text = segment.replace(/^[\s(]+/, "").replace(/[\s)]+$/, "");
  const masked = scanQuotes(text)?.masked ?? text;
  const words = wordsOf(text, masked);
  if (!words.length || CLOSING_KEYWORDS.has(words[0]!.text) || LOOP_HEADERS.has(words[0]!.text)) return;
  const first = skipPrefix(words, result);
  if (first < 0 || /[()]/.test(masked)) return markOpaque(text, result);
  if (first >= words.length) return;
  if (runsUnreadableCode(words, first)) return markOpaque(text, result);
  const name = baseName(words[first]!.text);
  const code = SHELL.test(name) ? shellCode(words, first) : undefined;
  if (code === null) return markOpaque(text, result);
  if (code !== undefined) return collectShellCode(code, text, result, depth);
  if (name === "xargs") {
    const operand = afterOptions(words, first + 1, XARGS_OPTIONS);
    if (operand < 0) return markOpaque(text, result);
    if (operand < words.length) {
      result.scoped = true;
      return collectSegment(text.slice(words[operand]!.start), result, depth);
    }
  }
  result.commands.push(text.slice(words[first]!.start));
  if (name === "find") collectFindExec(words, result, depth);
}

/*
 * The commands a Bash command really runs: control-flow keywords, groups and
 * transparent wrappers are removed so rules and approvals see the inner command.
 * Null where splitBashSegments is null.
 */
export function bashInnerCommands(command: string): InnerCommands | null {
  const segments = splitBashSegments(command);
  if (!segments) return null;
  const result: InnerCommands = { commands: [], opaque: false, elevated: false, scoped: false };
  for (const segment of segments) collectSegment(segment, result);
  return result;
}
