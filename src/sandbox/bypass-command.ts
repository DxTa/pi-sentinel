import { basename, isAbsolute } from "node:path";

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

export function shouldBypassSandboxCommand(command: string, patterns?: string[]): boolean {
  const trimmed = command.trim();
  if (trimmed.length === 0) return false;

  const configuredPatterns = patterns ?? [];
  if (configuredPatterns.some((pattern) => pattern.trim() === "*")) return true;
  if (containsShellControl(trimmed)) return false;
  if (builtinHostGitBypass(trimmed)) return true;
  return configuredPatterns.some((pattern) => wildcardMatch(pattern, trimmed));
}
