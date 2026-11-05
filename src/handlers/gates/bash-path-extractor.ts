import { createRequire } from "node:module";
import { basename } from "node:path";

import {
  isPathOutsideWorkingDirectory,
  normalizePathForComparison,
} from "#src/path-utils";

// ── tree-sitter-bash lazy parser ───────────────────────────────────────────

/**
 * Minimal subset of web-tree-sitter's SyntaxNode used by the AST walker.
 * Defined locally so callers do not need to import web-tree-sitter types.
 */
interface TSNode {
  readonly type: string;
  readonly text: string;
  readonly hasError?: boolean;
  readonly childCount: number;
  child(index: number): TSNode | null;
}

/**
 * Minimal subset of web-tree-sitter's Parser used by this module.
 */
interface TSParser {
  parse(input: string): { rootNode: TSNode; delete(): void } | null;
  delete(): void;
}

let parserPromise: Promise<TSParser> | null = null;
const DISABLE_TREE_SITTER_ENV = "PI_PERMISSION_SYSTEM_DISABLE_TREE_SITTER";

async function initParser(): Promise<TSParser> {
  // Use named imports — web-tree-sitter exports Parser as a named class.
  const { Parser, Language } = await import("web-tree-sitter");
  const req = createRequire(import.meta.url);
  const treeSitterWasm = req.resolve("web-tree-sitter/web-tree-sitter.wasm");
  await Parser.init({ locateFile: () => treeSitterWasm });

  const parser = new Parser();
  const bashWasm = req.resolve("tree-sitter-bash/tree-sitter-bash.wasm");
  const bash = await Language.load(bashWasm);
  parser.setLanguage(bash);
  return parser;
}

function shouldForceTokenizerFallback(): boolean {
  return process.env[DISABLE_TREE_SITTER_ENV] === "1";
}

function getParser(): Promise<TSParser> {
  parserPromise ??= initParser().catch((error) => {
    parserPromise = null;
    throw error;
  });
  return parserPromise;
}

/**
 * Reset the cached parser promise.  Only used by tests to avoid
 * cross-test pollution or to inject a mock parser.
 */
function resetParserForTesting(): void {
  parserPromise = null;
}

// ── AST walker ─────────────────────────────────────────────────────────────

/**
 * Node types whose subtrees must never be descended into for
 * path extraction — their text content is not a command argument.
 */
const SKIP_SUBTREE_TYPES = new Set(["heredoc_body", "heredoc_end", "comment"]);
const NON_EXECUTING_COMMAND_SUBTREE_TYPES = new Set([
  "function_definition",
  "if_statement",
  "for_statement",
  "while_statement",
  "until_statement",
  "case_statement",
]);
const UV_WRAPPER_NAMES = new Set(["env", "command", "exec", "sudo"]);

/**
 * Resolve the "shell value" of an argument node — the string the shell
 * would pass to the command after quote removal.
 *
 * - `word`          → `.text` (already unquoted)
 * - `raw_string`    → strip surrounding single quotes
 * - `string`        → strip surrounding double quotes, concatenate children text
 * - `concatenation` → concatenate resolved children
 * - other           → `.text` as fallback
 */
function resolveNodeText(node: TSNode): string {
  switch (node.type) {
    case "word":
      return node.text;
    case "raw_string": {
      // Strip surrounding single quotes: 'content' → content
      const t = node.text;
      if (t.length >= 2 && t.startsWith("'") && t.endsWith("'")) {
        return t.slice(1, -1);
      }
      return t;
    }
    case "string": {
      // Double-quoted string: concatenate the resolved text of inner children,
      // skipping the quote-delimiter nodes (literal `"`).
      let result = "";
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (!child) continue;
        // Skip the literal `"` delimiters
        if (child.type === '"') continue;
        result += resolveNodeText(child);
      }
      return result;
    }
    case "string_content":
    case "simple_expansion":
    case "expansion":
      return node.text;
    case "concatenation": {
      let result = "";
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (!child) continue;
        result += resolveNodeText(child);
      }
      return result;
    }
    default:
      return node.text;
  }
}

// ── Pattern-first command config ───────────────────────────────────────────

interface PatternCommandConfig {
  /** Flags that consume the next argument as a non-path value (pattern, separator, etc.) */
  readonly argConsumingFlags: ReadonlySet<string>;
  /** Flags that consume the next argument as a file path */
  readonly fileConsumingFlags: ReadonlySet<string>;
  /**
   * Number of leading positional arguments that are patterns/scripts, not paths.
   * Default: 1 (covers sed, awk, grep, rg).
   * sd uses 2 (FIND and REPLACE_WITH are both non-path positionals).
   */
  readonly patternPositionals?: number;
}

/**
 * Commands whose first N positional arguments are inline patterns/scripts,
 * not filesystem paths. The map stores per-command flag configuration so
 * the walker can correctly identify which arguments are consumed by flags
 * vs. which are positional.
 */
const PATTERN_FIRST_COMMANDS: ReadonlyMap<string, PatternCommandConfig> =
  new Map([
    [
      "sed",
      {
        argConsumingFlags: new Set(["-e", "-i"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "awk",
      {
        argConsumingFlags: new Set(["-e", "-F", "-v"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "gawk",
      {
        argConsumingFlags: new Set(["-e", "-F", "-v"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "nawk",
      {
        argConsumingFlags: new Set(["-e", "-F", "-v"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "grep",
      {
        argConsumingFlags: new Set(["-e", "-A", "-B", "-C", "-m"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "egrep",
      {
        argConsumingFlags: new Set(["-e", "-A", "-B", "-C", "-m"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "fgrep",
      {
        argConsumingFlags: new Set(["-e", "-A", "-B", "-C", "-m"]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "rg",
      {
        argConsumingFlags: new Set([
          "-e",
          "-A",
          "-B",
          "-C",
          "-m",
          "-g",
          "-t",
          "-T",
          "-j",
          "-M",
          "-r",
          "-E",
        ]),
        fileConsumingFlags: new Set(["-f"]),
      },
    ],
    [
      "sd",
      {
        argConsumingFlags: new Set(["-n", "-f"]),
        fileConsumingFlags: new Set([]),
        patternPositionals: 2,
      },
    ],
  ]);

/** Node types that represent argument values in the AST. */
const ARG_NODE_TYPES = new Set([
  "word",
  "concatenation",
  "string",
  "raw_string",
]);

/**
 * Extract the command name from a `command` node.
 * Returns the basename (e.g. `/usr/bin/sed` → `sed`), or undefined
 * if the command name cannot be determined (e.g. variable expansion).
 */
function extractCommandName(node: TSNode): string | undefined {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === "command_name") {
      const text = resolveNodeText(child);
      return text ? basename(text) : undefined;
    }
  }
  return undefined;
}

/**
 * Collect path-candidate tokens from a command known to have
 * pattern/script arguments in leading positional slots.
 *
 * Uses position-based skipping: the first N positional arguments
 * (where N = patternPositionals, default 1) are assumed to be
 * inline patterns/scripts and are skipped. Remaining positional
 * arguments are collected as path candidates.
 *
 * Flags listed in `argConsumingFlags` consume the next argument
 * (skipped). Flags in `fileConsumingFlags` consume the next
 * argument as a file path (collected). The flags `-e` and `-f`
 * additionally signal that an explicit script was provided via
 * flag, so no inline positional script is expected.
 */
function collectPatternCommandTokens(
  node: TSNode,
  tokens: string[],
  config: PatternCommandConfig,
): void {
  const patternPositionals = config.patternPositionals ?? 1;
  let hasExplicitScript = false;
  let positionalsSeen = 0;
  let nextArgAction: "skip" | "extract" | null = null;
  let pastEndOfFlags = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    // Skip command_name and variable_assignment nodes.
    if (child.type === "command_name" || child.type === "variable_assignment")
      continue;

    // Only process argument-like nodes; recurse into others
    // (e.g. command_substitution) for nested commands.
    if (!ARG_NODE_TYPES.has(child.type)) {
      collectPathCandidateTokens(child, tokens);
      continue;
    }

    const text = resolveNodeText(child);

    // Handle consumed argument from previous flag.
    if (nextArgAction === "skip") {
      nextArgAction = null;
      continue;
    }
    if (nextArgAction === "extract") {
      tokens.push(text);
      nextArgAction = null;
      continue;
    }

    // Flag detection (only before "--" end-of-flags marker).
    if (
      !pastEndOfFlags &&
      child.type === "word" &&
      text.startsWith("-") &&
      text.length > 1
    ) {
      if (text === "--") {
        pastEndOfFlags = true;
        continue;
      }
      if (config.argConsumingFlags.has(text)) {
        nextArgAction = "skip";
        if (text === "-e" || text === "-f") {
          hasExplicitScript = true;
        }
        continue;
      }
      if (config.fileConsumingFlags.has(text)) {
        nextArgAction = "extract";
        hasExplicitScript = true;
        continue;
      }
      // Regular flag — skip it.
      continue;
    }

    // Positional argument.
    if (!hasExplicitScript && positionalsSeen < patternPositionals) {
      positionalsSeen++;
      continue; // Skip: this is an inline pattern/script.
    }

    // File argument — collect as path candidate.
    tokens.push(text);
  }
}

/**
 * Recursively visit the AST and collect resolved text of nodes that
 * represent command arguments or redirect destinations.
 *
 * Skips `heredoc_body`, `heredoc_end`, and `comment` subtrees entirely.
 *
 * For commands in `PATTERN_FIRST_COMMANDS`, uses position-based
 * argument skipping to avoid collecting inline patterns/scripts
 * as path candidates. For all other commands, collects all
 * arguments generically.
 */
function collectPathCandidateTokens(node: TSNode, tokens: string[]): void {
  if (SKIP_SUBTREE_TYPES.has(node.type)) return;

  // Extract arguments from `command` nodes.
  if (node.type === "command") {
    const commandName = extractCommandName(node);
    const patternConfig = commandName
      ? PATTERN_FIRST_COMMANDS.get(commandName)
      : undefined;

    if (patternConfig) {
      collectPatternCommandTokens(node, tokens, patternConfig);
      return;
    }

    // Generic extraction: collect all arguments (skip command name).
    let seenCommandName = false;
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (!child) continue;

      if (child.type === "command_name") {
        seenCommandName = true;
        continue;
      }
      // Skip variable_assignment nodes (FOO=/bar)
      if (child.type === "variable_assignment") continue;

      // If there was no explicit command_name node, the first word-like
      // child is the command name itself — skip it.
      if (!seenCommandName && ARG_NODE_TYPES.has(child.type)) {
        seenCommandName = true;
        continue;
      }

      // Argument nodes: resolve their text and collect.
      if (ARG_NODE_TYPES.has(child.type)) {
        tokens.push(resolveNodeText(child));
        continue;
      }

      // Recurse into other children (e.g. command_substitution nested in args)
      collectPathCandidateTokens(child, tokens);
    }
    return;
  }

  // Extract redirect destinations from `file_redirect` nodes.
  if (node.type === "file_redirect") {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (!child) continue;
      if (
        child.type === "word" ||
        child.type === "concatenation" ||
        child.type === "string" ||
        child.type === "raw_string"
      ) {
        tokens.push(resolveNodeText(child));
      }
    }
    return;
  }

  // For all other node types, recurse into children.
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    collectPathCandidateTokens(child, tokens);
  }
}

const WRITE_REDIRECT_TYPES = new Set([">", ">>", ">|", ">&", "&>", "&>>", "&>|"]);
const REDIRECT_TARGET_TYPES = new Set(["word", "concatenation", "string", "raw_string"]);
const UNSUPPORTED_REDIRECT_TARGET_TYPES = new Set(["ansi_c_string", "translated_string"]);

class UnsupportedWriteRedirectError extends Error {
  constructor() {
    super("Unsupported Bash output redirect target quoting.");
  }
}

function collectWriteRedirectTokens(node: TSNode, tokens: string[]): void {
  if (SKIP_SUBTREE_TYPES.has(node.type)) return;

  if (node.type === "file_redirect") {
    let afterWriteOperator = false;
    for (let index = 0; index < node.childCount; index += 1) {
      const child = node.child(index);
      if (!child) continue;
      if (WRITE_REDIRECT_TYPES.has(child.type)) {
        afterWriteOperator = true;
        continue;
      }
      if (afterWriteOperator && UNSUPPORTED_REDIRECT_TARGET_TYPES.has(child.type)) {
        throw new UnsupportedWriteRedirectError();
      }
      if (afterWriteOperator && REDIRECT_TARGET_TYPES.has(child.type)) {
        tokens.push(resolveNodeText(child));
        break;
      }
    }
    return;
  }

  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) collectWriteRedirectTokens(child, tokens);
  }
}

const WRITE_COMMAND_NAMES = new Set(["cp", "mv", "install", "ln", "touch", "tee", "dd"]);

/** Operands of write commands. Every operand counts, copy sources included, so the check fails closed. */
function collectWriteCommandTokens(node: TSNode, tokens: string[]): void {
  if (SKIP_SUBTREE_TYPES.has(node.type)) return;

  if (node.type === "command") {
    const name = extractCommandName(node);
    if (name !== undefined && WRITE_COMMAND_NAMES.has(name)) {
      for (let index = 0; index < node.childCount; index += 1) {
        const child = node.child(index);
        if (!child || child.type === "command_name" || child.type === "file_redirect") continue;
        const text = resolveNodeText(child);
        if (name === "dd") {
          if (text.startsWith("of=")) tokens.push(text.slice("of=".length));
        } else if (!text.startsWith("-")) {
          tokens.push(text);
        }
      }
    }
  }

  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child) collectWriteCommandTokens(child, tokens);
  }
}

const SHELL_CONTROL_OPERATORS = new Set([";", "&&", "||", "|", "(", ")"]);
const SHELL_REDIRECT_OPERATOR_PATTERN = /^(?:\d+)?(?:>>?|<<?|<>?)$/;
const SHELL_ASSIGNMENT_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*=.*/;

function splitShellWords(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "single" | "double" | null = null;
  let escaping = false;

  for (const char of command) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }

    if (quote === "single") {
      if (char === "'") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (quote === "double") {
      if (char === '"') {
        quote = null;
        continue;
      }
      if (char === "\\") {
        escaping = true;
        continue;
      }
      current += char;
      continue;
    }

    if (char === "\\") {
      escaping = true;
      continue;
    }
    if (char === "'") {
      quote = "single";
      continue;
    }
    if (char === '"') {
      quote = "double";
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (escaping) {
    current += "\\";
  }
  if (current) {
    tokens.push(current);
  }
  return tokens;
}

function isShellAssignmentToken(token: string): boolean {
  return SHELL_ASSIGNMENT_PATTERN.test(token);
}

function collectPathCandidateTokensFallback(command: string): string[] {
  const extracted: string[] = [];
  const shellWords = splitShellWords(command);
  let patternConfig: PatternCommandConfig | undefined;
  let patternPositionals = 1;
  let hasExplicitScript = false;
  let positionalsSeen = 0;
  let nextArgAction: "skip" | "extract" | null = null;
  let pastEndOfFlags = false;
  let expectingRedirectTarget = false;
  let seenCommandName = false;

  const resetCommandState = () => {
    patternConfig = undefined;
    patternPositionals = 1;
    hasExplicitScript = false;
    positionalsSeen = 0;
    nextArgAction = null;
    pastEndOfFlags = false;
    expectingRedirectTarget = false;
    seenCommandName = false;
  };

  resetCommandState();

  for (const token of shellWords) {
    if (!token) {
      continue;
    }

    if (SHELL_CONTROL_OPERATORS.has(token)) {
      resetCommandState();
      continue;
    }

    if (SHELL_REDIRECT_OPERATOR_PATTERN.test(token)) {
      expectingRedirectTarget = true;
      continue;
    }

    if (expectingRedirectTarget) {
      extracted.push(token);
      expectingRedirectTarget = false;
      continue;
    }

    if (!seenCommandName) {
      if (isShellAssignmentToken(token)) {
        continue;
      }
      seenCommandName = true;
      patternConfig = PATTERN_FIRST_COMMANDS.get(basename(token));
      patternPositionals = patternConfig?.patternPositionals ?? 1;
      continue;
    }

    if (isShellAssignmentToken(token)) {
      continue;
    }

    if (nextArgAction === "skip") {
      nextArgAction = null;
      continue;
    }
    if (nextArgAction === "extract") {
      extracted.push(token);
      nextArgAction = null;
      continue;
    }

    if (
      patternConfig &&
      !pastEndOfFlags &&
      token.startsWith("-") &&
      token.length > 1
    ) {
      if (token === "--") {
        pastEndOfFlags = true;
        continue;
      }
      if (patternConfig.argConsumingFlags.has(token)) {
        nextArgAction = "skip";
        if (token === "-e" || token === "-f") {
          hasExplicitScript = true;
        }
        continue;
      }
      if (patternConfig.fileConsumingFlags.has(token)) {
        nextArgAction = "extract";
        hasExplicitScript = true;
        continue;
      }
      continue;
    }

    if (patternConfig && !hasExplicitScript && positionalsSeen < patternPositionals) {
      positionalsSeen++;
      continue;
    }

    extracted.push(token);
  }

  return extracted;
}

interface HereDocSpec {
  readonly delimiter: string;
  readonly stripTabs: boolean;
}

type ShellQuote = "'" | '"' | null;

function isEscaped(line: string, index: number): boolean {
  let backslashes = 0;
  for (let cursor = index - 1; cursor >= 0 && line[cursor] === "\\"; cursor -= 1) {
    backslashes += 1;
  }
  return backslashes % 2 === 1;
}

interface HereDocDelimiter {
  readonly delimiter: string;
  readonly nextIndex: number;
  readonly unsupported: boolean;
}

function parseHereDocDelimiter(line: string, start: number): HereDocDelimiter {
  let cursor = start;
  let quote: "'" | '"' | null = null;
  let delimiter = "";
  let unsupported = false;

  while (cursor < line.length) {
    const char = line[cursor]!;
    if (quote === "'") {
      if (char === "'") quote = null;
      else delimiter += char;
      cursor += 1;
      continue;
    }
    if (quote === '"') {
      if (char === '"') {
        quote = null;
        cursor += 1;
      } else if (char === "\\" && cursor + 1 < line.length) {
        delimiter += line[cursor + 1]!;
        cursor += 2;
      } else {
        delimiter += char;
        cursor += 1;
      }
      continue;
    }
    if (/[\t ;|&<>]/.test(char)) break;
    if (char === "'" || char === '"') {
      quote = char;
      cursor += 1;
    } else if (char === "\\" && cursor + 1 < line.length) {
      delimiter += line[cursor + 1]!;
      cursor += 2;
    } else {
      if (char === "$" || char === "`") unsupported = true;
      delimiter += char;
      cursor += 1;
    }
  }

  return {
    delimiter,
    nextIndex: cursor,
    unsupported: unsupported || quote !== null || delimiter.length === 0,
  };
}

interface HereDocScanResult {
  readonly specs: HereDocSpec[];
  readonly quote: ShellQuote;
  readonly unsupported: boolean;
}

function findHereDocSpecs(line: string, initialQuote: ShellQuote): HereDocScanResult {
  const specs: HereDocSpec[] = [];
  let quote = initialQuote;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index]!;
    if (quote === "'") {
      if (char === "'") quote = null;
      continue;
    }
    if (quote === '"') {
      if (char === '"' && !isEscaped(line, index)) quote = null;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "\\") {
      index += 1;
      continue;
    }
    if (char === "#" && (index === 0 || /[\s;|&()]/.test(line[index - 1]!))) break;
    if (char !== "<" || line[index + 1] !== "<" || line[index + 2] === "<") continue;

    let cursor = index + 2;
    const stripTabs = line[cursor] === "-";
    if (stripTabs) cursor += 1;
    while (/[\t ]/.test(line[cursor] ?? "")) cursor += 1;
    const delimiter = parseHereDocDelimiter(line, cursor);
    if (delimiter.unsupported) return { specs, quote, unsupported: true };
    specs.push({ delimiter: delimiter.delimiter, stripTabs });
    index = delimiter.nextIndex - 1;
  }
  return { specs, quote, unsupported: false };
}

function stripHeredocBodies(command: string): string | null {
  let pending: HereDocSpec[] = [];
  let quote: ShellQuote = null;
  let unsupported = false;
  const lines = command.split("\n").map((line) => {
    if (pending.length > 0) {
      const heredoc = pending[0]!;
      const candidate = heredoc.stripTabs ? line.replace(/^\t+/, "") : line;
      if (candidate === heredoc.delimiter) {
        pending = pending.slice(1);
        return line;
      }
      return " ".repeat(line.length);
    }
    const result = findHereDocSpecs(line, quote);
    if (result.unsupported) {
      unsupported = true;
      return line;
    }
    pending = result.specs;
    quote = result.quote;
    return line;
  });
  return unsupported ? null : lines.join("\n");
}

function isUvExecutable(text: string): boolean {
  const name = basename(text);
  return name === "uv" || name === "uvx";
}

function extractUvExecutable(node: TSNode): boolean {
  const commandName = extractCommandName(node);
  if (!commandName) return false;
  if (isUvExecutable(commandName)) return true;
  if (!UV_WRAPPER_NAMES.has(commandName)) return false;

  const args: string[] = [];
  let seenCommandName = false;
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (!child) continue;
    if (child.type === "command_name") {
      seenCommandName = true;
      continue;
    }
    if (child.type === "variable_assignment") continue;
    if (!seenCommandName && ARG_NODE_TYPES.has(child.type)) {
      seenCommandName = true;
      continue;
    }
    if (ARG_NODE_TYPES.has(child.type)) args.push(resolveNodeText(child));
  }

  if (commandName === "env") {
    for (const arg of args) {
      if (arg === "--") continue;
      if (arg.startsWith("-") || SHELL_ASSIGNMENT_PATTERN.test(arg)) continue;
      return isUvExecutable(arg);
    }
    return false;
  }
  return args.length > 0 && isUvExecutable(args[0]!);
}


/** `cd <dir> && uv ...` as a whole top-level chain: cd cannot skip uv, so uv runs as a plain command. */
function isCdThenUvChain(node: TSNode): boolean {
  const operands: TSNode[] = [];
  if (!collectAndChainOperands(node, operands)) return false;
  let hasUv = false;
  for (const operand of operands) {
    if (extractUvExecutable(operand)) {
      hasUv = true;
    } else if (extractCommandName(operand) !== "cd") {
      return false;
    }
  }
  return hasUv;
}

function collectAndChainOperands(node: TSNode, out: TSNode[]): boolean {
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (!child || child.type === "&&") continue;
    if (child.type === "list") {
      if (!collectAndChainOperands(child, out)) return false;
    } else if (child.type === "command") {
      out.push(child);
    } else {
      return false;
    }
  }
  return true;
}

function containsUvCommand(node: TSNode, inBooleanList = false): boolean {
  if (SKIP_SUBTREE_TYPES.has(node.type) || NON_EXECUTING_COMMAND_SUBTREE_TYPES.has(node.type)) {
    return false;
  }
  const booleanContext = inBooleanList || (node.type === "list" && /&&|\|\|/.test(node.text));
  if (node.type === "list" && !inBooleanList && isCdThenUvChain(node)) return true;
  if (node.type === "command" && !booleanContext && extractUvExecutable(node)) {
    return true;
  }
  for (let index = 0; index < node.childCount; index += 1) {
    const child = node.child(index);
    if (child && containsUvCommand(child, booleanContext)) return true;
  }
  return false;
}


/** Detect literal uv/uvx command nodes; parser failure uses strict fallback. */
export async function commandContainsUvExecutable(command: string): Promise<boolean> {
  if (shouldForceTokenizerFallback()) return false;

  try {
    const parser = await getParser();
    const sanitizedCommand = stripHeredocBodies(command);
    if (sanitizedCommand === null) return false;
    const tree = parser.parse(sanitizedCommand);
    if (!tree) return false;
    try {
      return containsUvCommand(tree.rootNode);
    } finally {
      tree.delete();
    }
  } catch {
    return false;
  }
}

async function extractPathCandidateTokens(command: string): Promise<string[]> {
  if (shouldForceTokenizerFallback()) {
    return collectPathCandidateTokensFallback(command);
  }

  try {
    const parser = await getParser();
    const tree = parser.parse(command);
    if (!tree) {
      return collectPathCandidateTokensFallback(command);
    }

    const tokens: string[] = [];
    try {
      collectPathCandidateTokens(tree.rootNode, tokens);
    } finally {
      tree.delete();
    }
    return tokens;
  } catch {
    return collectPathCandidateTokensFallback(command);
  }
}

/**
 * URL pattern to skip tokens that look like URLs rather than paths.
 */
const URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Regex metacharacter sequences that are never found in real filesystem paths.
 * If a token contains any of these, it is almost certainly a regex pattern
 * (e.g. a grep argument) rather than a path.
 */
const REGEX_METACHAR_PATTERN = /\.\*|\.\+|\\\||\\\(|\\\)|\[.*?\]|\^\//;

/** Path value of a `NAME=value` / `--opt=value` token when `isPath` accepts it, else null. */
function assignmentPathValue(token: string, isPath: (value: string) => boolean): string | null {
  const value = token.slice(token.indexOf("=") + 1);
  return value && !URL_PATTERN.test(value) && isPath(value) ? value : null;
}

/**
 * Broader token classification for cross-cutting `path` rules.
 *
 * Accepts the same rejections as `classifyTokenAsPathCandidate` (empty, flags,
 * env assignments, URLs, @scope/package, repeated-slash markers, regex metacharacters),
 * but also accepts:
 * - Tokens starting with `.` (dot-files: `.env`, `./src`)
 * - Tokens containing `/` (relative paths: `src/foo.ts`)
 *
 * Does NOT require the strict "must start with `/` or `~/` or contain `..`"
 * gate that the external-directory classifier uses.
 */
function classifyTokenAsRuleCandidate(token: string): string | null {
  if (!token) return null;

  if (token.includes("=")) {
    return assignmentPathValue(token, (value) => value.startsWith(".") || value.includes("/"));
  }
  if (token.startsWith("-")) return null;

  if (URL_PATTERN.test(token)) return null;
  if (token.startsWith("@") && !token.startsWith("@/")) return null;
  if (/^\/{2,}$/.test(token)) return null;
  if (REGEX_METACHAR_PATTERN.test(token)) return null;

  // Accept: starts with . (dot-files, ./ relative), contains / (paths),
  // starts with / or ~/ (absolute/home), or contains .. (parent traversal).
  if (token.startsWith(".")) return token;
  if (token.includes("/")) return token;
  if (token.startsWith("~/")) return token;
  if (token.includes("..")) return token;

  return null;
}

/**
 * Determines whether a token looks like a path candidate worth resolving.
 * Returns the raw token string if it's a candidate, or null to skip.
 */
function classifyTokenAsPathCandidate(token: string): string | null {
  // Skip empty tokens
  if (!token) return null;

  if (token.includes("=")) {
    return assignmentPathValue(token, (value) => /^(\/|~\/|\.\/|\.\.\/)/.test(value));
  }

  // Skip flags without a path value
  if (token.startsWith("-")) return null;

  // Skip URLs
  if (URL_PATTERN.test(token)) return null;

  // Skip @scope/package patterns
  if (token.startsWith("@") && !token.startsWith("@/")) return null;

  // Preserve `/` as an explicit filesystem-root argument; ignore multi-slash markers.
  if (/^\/{2,}$/.test(token)) return null;

  // Skip tokens that contain regex metacharacter sequences — these are almost
  // certainly grep/sed/awk patterns, not filesystem paths.
  // Matches: .*, .+, \|, \(, \), [...], or ^/ (anchored regex starting with /)
  if (REGEX_METACHAR_PATTERN.test(token)) return null;

  // Must look like a path: starts with /, ~/, or contains ..
  if (token.startsWith("/")) return token;
  if (token.startsWith("~/")) return token;
  if (token.includes("..")) return token;

  return null;
}

/**
 * Extracts paths from a bash command string that resolve outside CWD.
 * Uses tree-sitter-bash to parse the command into a full AST, then walks
 * command argument and redirect-destination nodes.  Heredoc bodies, comments,
 * and other non-argument content are skipped, eliminating false positives.
 */
export async function extractExternalPathsFromBashCommand(
  command: string,
  cwd: string,
): Promise<string[]> {
  const tokens = await extractPathCandidateTokens(command);

  const seen = new Set<string>();
  const externalPaths: string[] = [];

  for (const token of tokens) {
    const candidate = classifyTokenAsPathCandidate(token);
    if (!candidate) continue;

    const normalized = normalizePathForComparison(candidate, cwd);
    if (!normalized) continue;

    if (
      isPathOutsideWorkingDirectory(candidate, cwd) &&
      !seen.has(normalized)
    ) {
      seen.add(normalized);
      externalPaths.push(normalized);
    }
  }

  return externalPaths;
}

/**
 * Extract tokens from a bash command that may be file paths, using a broader
 * filter suitable for cross-cutting `path` permission rules.
 *
 * Unlike `extractExternalPathsFromBashCommand`, this function:
 * - Accepts relative paths (`.env`, `src/foo.ts`, `./build`)
 * - Does NOT filter by CWD — returns raw tokens for rule evaluation
 * - Returns deduplicated tokens
 */
export async function extractTokensForPathRules(
  command: string,
): Promise<string[]> {
  const tokens = await extractPathCandidateTokens(command);

  const seen = new Set<string>();
  const result: string[] = [];

  for (const token of tokens) {
    const candidate = classifyTokenAsRuleCandidate(token);
    if (!candidate) continue;
    if (!seen.has(candidate)) {
      seen.add(candidate);
      result.push(candidate);
    }
  }

  return result;
}


/** Extract literal external file targets from parsed output redirections only. */
export async function extractExternalWritePathsFromBashCommand(command: string, cwd: string): Promise<string[]> {
  const tokens = await parseWriteTokens(command);
  if (!tokens) return [];
  return normalizeWriteTokens(tokens.redirects, cwd, (candidate) => isPathOutsideWorkingDirectory(candidate, cwd));
}

export class UnverifiableBashCommandError extends Error {
  constructor() {
    super("Unable to verify Bash write targets.");
  }
}

/** Every write target, inside or outside cwd. Throws when the command cannot be parsed, so callers fail closed. */
export async function extractAllWriteTargetsFromBashCommand(command: string, cwd: string): Promise<string[]> {
  const tokens = await parseWriteTokens(command);
  if (!tokens) throw new UnverifiableBashCommandError();
  const paths = new Set<string>();
  for (const token of [...tokens.redirects, ...tokens.commands]) {
    // A bare digit is a descriptor duplicate (`2>&1`), not a file. Relative names count: the check covers in-project writes.
    if (!token || /^\d+$/.test(token)) continue;
    paths.add(normalizePathForComparison(token, cwd));
  }
  return [...paths];
}

type WriteTokens = { redirects: string[]; commands: string[] };

/** Null when the command cannot be parsed; each caller decides whether that fails open or closed. */
async function parseWriteTokens(command: string): Promise<WriteTokens | null> {
  if (shouldForceTokenizerFallback()) return null;

  let tree: ReturnType<TSParser["parse"]> | null = null;
  try {
    const parser = await getParser();
    tree = parser.parse(command);
    if (!tree || tree.rootNode.hasError !== false) return null;

    const redirects: string[] = [];
    collectWriteRedirectTokens(tree.rootNode, redirects);
    const commands: string[] = [];
    collectWriteCommandTokens(tree.rootNode, commands);
    return { redirects, commands };
  } catch (error) {
    if (error instanceof UnsupportedWriteRedirectError) throw error;
    return null;
  } finally {
    tree?.delete();
  }
}

function normalizeWriteTokens(tokens: string[], cwd: string, keep: (candidate: string) => boolean): string[] {
  const paths = new Set<string>();
  for (const token of tokens) {
    const candidate = classifyTokenAsPathCandidate(token);
    if (!candidate || !keep(candidate)) continue;
    const normalized = normalizePathForComparison(candidate, cwd);
    if (normalized) paths.add(normalized);
  }
  return [...paths];
}
