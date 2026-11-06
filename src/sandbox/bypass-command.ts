import { basename, isAbsolute } from "node:path";

import { prefix } from "../bash-arity.js";
import { bashInnerCommands, bashLiteralWords, bashWordsWithoutRedirections, splitBashSegments } from "../bash-segments.js";
import { wildcardMatch } from "../wildcard-matcher.js";

const BUILTIN_HOST_GIT_SUBCOMMANDS = new Set([
  "clone",
  "fetch",
  "ls-remote",
  "pull",
  "push",
  "submodule",
]);

function containsShellControl(command: string): boolean {
  for (const character of "&;|<>`") {
    if (command.includes(character)) return true;
  }
  return command.includes("$(") || command.includes("\n");
}

function builtinHostGitBypass(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed.startsWith("git ")) return false;
  if (containsShellControl(trimmed)) return false;

  const tokens = trimmed.split(/\s+/);
  const subcommand = tokens[1];
  return subcommand != null && BUILTIN_HOST_GIT_SUBCOMMANDS.has(subcommand);
}

function isDirectExecutable(value: string, name: string): boolean {
  return value === name || (isAbsolute(value) && basename(value) === name);
}

/**
 * Recognize only direct package/bootstrap commands that may need host tools.
 * Shell composition and indirect wrappers stay sandboxed/rejected.
 */
export function isHostCapabilityBootstrapCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || containsShellControl(trimmed)) return false;
  const tokens = trimmed.split(/\s+/);
  const executable = tokens[0] ?? "";
  if (isDirectExecutable(executable, "pkgx")) return true;
  if (
    !isDirectExecutable(executable, "python")
    && !/^python\d+(?:\.\d+)*$/.test(executable)
    && !(isAbsolute(executable) && /^python\d*(?:\.\d+)*$/.test(basename(executable)))
  ) {
    return false;
  }
  return tokens[1] === "-m" && tokens[2] === "venv";
}

function isDockerExecutable(executable: string): boolean {
  return executable === "docker"
    || executable === "docker-compose"
    || executable.endsWith("/docker")
    || executable.endsWith("/docker-compose");
}

export function isDockerCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || containsShellControl(trimmed)) return false;
  const executable = trimmed.split(/\s+/, 1)[0] ?? "";
  return isDockerExecutable(executable);
}

function normalizeEscapedShellWordCharacters(command: string): string {
  return command.replace(/\\([A-Za-z-])/g, "$1");
}

function dockerCommandWords(segment: string): string[] | null {
  return bashLiteralWords(segment) ?? bashWordsWithoutRedirections(segment);
}

function isDockerClientOnly(words: string[]): boolean {
  const args = words.slice(1);
  return args[0] === "help"
    || (args.length === 1 && ["--help", "-h", "--version", "-v"].includes(args[0] ?? ""));
}

/** True when every command segment's arity prefix (e.g. "docker build") is a granted host-fallback prefix. */
export function isHostFallbackGranted(command: string, grants: readonly string[]): boolean {
  if (grants.length === 0) return false;
  const segments = splitBashSegments(command);
  if (!segments || segments.length === 0) return false;
  // Literal words of the raw segment: a wrapper, env assignment or redirect makes the prefix miss.
  return segments.every((segment) => {
    if (/[<>]/.test(segment)) return false;
    const words = bashLiteralWords(segment);
    return words !== null && grants.includes(prefix(words).join(" "));
  });
}

export function isDockerDaemonCommand(command: string): boolean {
  const normalized = normalizeEscapedShellWordCharacters(command);
  const parsed = bashInnerCommands(command) ?? bashInnerCommands(normalized);
  if (!parsed) return /\b(?:docker|docker-compose)\b/.test(normalized);

  const commands = parsed.commands.map(dockerCommandWords);
  if (commands.some((words) =>
    words !== null && isDockerExecutable(words[0] ?? "") && !isDockerClientOnly(words),
  )) return true;
  return parsed.opaque
    && !commands.some((words) => words !== null && isDockerExecutable(words[0] ?? "") && isDockerClientOnly(words))
    && /\b(?:docker|docker-compose)\b/.test(normalized);
}

const DOCKER_GLOBAL_VALUE_OPTIONS = new Set([
  "--config", "--context", "--host", "-c", "-H", "--log-level",
  "--tlscacert", "--tlscert", "--tlskey",
]);

function hasDockerEndpointGlobalOption(args: string[]): boolean {
  const firstCommandArg = args.findIndex((arg) => arg === "--"
    || (!arg.startsWith("-") && !/[$`]/.test(arg)));
  const options = firstCommandArg < 0 ? args : args.slice(0, firstCommandArg);
  return options.some((arg) => /[$`]/.test(arg)
    || DOCKER_GLOBAL_VALUE_OPTIONS.has(arg.split("=", 1)[0]!)
    || /^-(?:H|c)/.test(arg));
}

function mutatesDockerEndpointEnvironment(segment: string): boolean {
  const words = dockerCommandWords(segment);
  if (!words?.length) return false;
  const assignmentOnly = words.every((word) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(word));
  if (assignmentOnly && words.some((word) => /^DOCKER_(?:HOST|CONTEXT|CONFIG)=/.test(word))) return true;

  const commandIndex = words[0] === "builtin" ? 1 : 0;
  const command = words[commandIndex];
  const args = words.slice(commandIndex + 1);
  if (["export", "unset", "declare", "typeset", "read"].includes(command ?? "")) {
    return args.some((arg) => /^DOCKER_(?:HOST|CONTEXT|CONFIG)(?:=|$)/.test(arg) || /[$`]/.test(arg));
  }
  if (command === "printf") {
    return args[0] === "-v" && (/^DOCKER_(?:HOST|CONTEXT|CONFIG)$/.test(args[1] ?? "") || /[$`]/.test(args[1] ?? ""));
  }
  return command === "eval" || command === "source" || command === ".";
}

function hasDockerEndpointEnvironmentReset(prefix: string[]): boolean {
  const envIndex = prefix.findIndex((word) => isDirectExecutable(word, "env"));
  if (envIndex < 0) return false;
  const args = prefix.slice(envIndex + 1).join(" ");
  return /(?:^|\s)(?:-i|--ignore-environment)(?:\s|$)/.test(args)
    || /(?:^|\s)(?:-u\s*DOCKER_(?:HOST|CONTEXT|CONFIG)|--unset(?:=|\s+)DOCKER_(?:HOST|CONTEXT|CONFIG))(?:\s|$)/.test(args);
}

function simpleCommandHasDockerEndpointOverride(segment: string): boolean {
  const words = dockerCommandWords(segment);
  if (!words) return false;

  const dockerIndex = words.findIndex((word) => isDockerExecutable(word));
  if (dockerIndex < 0) return false;
  const prefix = words.slice(0, dockerIndex);
  const args = words.slice(dockerIndex + 1);
  return prefix.some((word) => /^DOCKER_(?:HOST|CONTEXT|CONFIG)=/.test(word))
    || hasDockerEndpointEnvironmentReset(prefix)
    || hasDockerEndpointGlobalOption(args);
}

function hasOpaqueDockerEnvironmentMutation(command: string): boolean {
  if (/\bDOCKER_(?:HOST|CONTEXT|CONFIG)=[^\r\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\b(?:export|unset|declare|typeset|read)\b[^\r\n]*\bDOCKER_(?:HOST|CONTEXT|CONFIG)\b[^\r\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\benv\b[^\r\n]*?(?:--ignore-environment|(?:^|\s)-i(?:\s|$)|--unset(?:=|\s+)|-u\s*)[^\r\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  return false;
}

function segmentHasDockerEndpointOverride(segment: string, depth = 0): boolean {
  const words = dockerCommandWords(segment);
  if (!words) return isDockerDaemonCommand(segment) && hasOpaqueDockerEndpointSelector(segment);
  if (simpleCommandHasDockerEndpointOverride(segment)) return true;
  if (depth >= 3) return false;

  const parsed = bashInnerCommands(segment);
  if (parsed?.opaque && hasOpaqueDockerEndpointSelector(segment)) return true;
  if (parsed?.scoped && hasOpaqueDockerEnvironmentMutation(segment)) return true;
  const nestedCommands = parsed?.commands;
  return nestedCommands?.some((nested) => nested !== segment)
    ? hasDockerEndpointOverrideInSegments(nestedCommands, depth + 1)
    : false;
}

function hasDockerEndpointOverrideInSegments(segments: string[], depth = 0): boolean {
  let endpointEnvironmentChanged = false;
  for (const segment of segments) {
    if (endpointEnvironmentChanged && isDockerDaemonCommand(segment)) return true;
    if (segmentHasDockerEndpointOverride(segment, depth)) return true;
    if (mutatesDockerEndpointEnvironment(segment)) endpointEnvironmentChanged = true;
  }
  return false;
}

function hasOpaqueDockerEndpointSelector(command: string): boolean {
  if (/(?:^|[\s"'(])(?:--host|--context|-H|-c)(?:=|\s)/.test(command)) return true;
  if (/\bDOCKER_(?:HOST|CONTEXT|CONFIG)=[^\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\b(?:export|unset|declare|typeset|read)\b[^\n]*\bDOCKER_(?:HOST|CONTEXT|CONFIG)\b[^\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\b(?:export|unset|declare|typeset|read)\b[^\n]*[$`][^\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\benv\b[^\n]*?(?:--ignore-environment|(?:^|\s)-i(?:\s|$))[^\r\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\benv\b[^\n]*?(?:--unset(?:=|\s+)|-u\s*)DOCKER_(?:HOST|CONTEXT|CONFIG)\b[^\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\benv\b[^\n]*?(?:-S\s+|--split-string(?:=|\s+))[^\n]*(?:-i|--ignore-environment|-u\s*DOCKER_(?:HOST|CONTEXT|CONFIG)|--unset(?:=|\s+)DOCKER_(?:HOST|CONTEXT|CONFIG)|DOCKER_(?:HOST|CONTEXT|CONFIG)=)[^\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/\b(?:eval|source)\b[^\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  if (/(?:^|[;&]\s*)\.\s+[^\n]*\bdocker(?:-compose)?\b/.test(command)) return true;
  return /\bdocker(?:-compose)?\s+(?:--\S+\s+)*["']?\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\}|[@*])/.test(command);
}

export function hasDockerEndpointOverride(command: string): boolean {
  if (!isDockerDaemonCommand(command)) return false;
  const normalized = normalizeEscapedShellWordCharacters(command);
  const segments = splitBashSegments(command) ?? splitBashSegments(normalized);
  return segments
    ? hasDockerEndpointOverrideInSegments(segments)
    : hasOpaqueDockerEndpointSelector(normalized);
}

export function shouldBypassSandboxCommand(command: string, patterns?: string[]): boolean {
  const trimmed = command.trim();
  if (trimmed.length === 0) return false;

  const configuredPatterns = patterns ?? [];
  if (configuredPatterns.some((pattern) => pattern.trim() === "*")) return true;
  if (containsShellControl(trimmed)) return false;
  if (builtinHostGitBypass(trimmed)) return true;
  return configuredPatterns.some((pattern) => wildcardMatch(pattern, trimmed));
}
