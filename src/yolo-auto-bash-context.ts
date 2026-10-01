import { homedir } from "node:os";
import { relative } from "node:path";

import { extractAllNetworkTargets } from "./network/domain-extractor.js";
import { isPathWithinCanonicalWorkingDirectory, normalizePathForComparison } from "./path-utils.js";
import { isSensitivePath } from "./yolo-auto-sensitive-paths.js";

const ABSOLUTE_PATH_PATTERN = /(^|[\s"'=\x3e])((?:~\/|\/)[^\s"'\x3c\x3e;\x26|]+)/g;
const OPEN_ANGLE = String.fromCharCode(60);
const CLOSE_ANGLE = String.fromCharCode(62);
const SENSITIVE_PATH = OPEN_ANGLE + "sensitive-path" + CLOSE_ANGLE;
const EXTERNAL_PATH = OPEN_ANGLE + "external-path" + CLOSE_ANGLE;
const PATH = OPEN_ANGLE + "path" + CLOSE_ANGLE;

export interface YoloAutoBashContext {
  command: string;
  workspaceLocal: boolean;
  hardRuleHit: boolean;
}

/** Redact filesystem operands and mark Bash commands safe for classifier use. */
export function buildYoloAutoBashContext(
  command: string,
  pathTokens: readonly string[],
  cwd: string | undefined,
): YoloAutoBashContext {
  let workspaceLocal = Boolean(cwd);
  let hardRuleHit = false;
  let sanitizedCommand = command;
  const tokens = [...new Set(pathTokens)].filter(Boolean).sort((left, right) => right.length - left.length);

  for (const token of tokens) {
    const dynamicPath = token.includes("$") || token.includes(String.fromCharCode(96));
    const networkAddress = token.includes("://");
    const normalizedPath = normalizePathForComparison(token, cwd ?? "/");
    const sensitivePath = dynamicPath ? true : networkAddress ? false : isSensitivePath(normalizedPath, homedir());
    const workspacePath = !dynamicPath && !networkAddress
      ? cwd ? isPathWithinCanonicalWorkingDirectory(token, cwd) : false
      : false;
    hardRuleHit = hardRuleHit || sensitivePath;
    workspaceLocal = workspaceLocal ? workspacePath : false;

    const safePath = sensitivePath
      ? SENSITIVE_PATH
      : workspacePath
        ? relative(cwd!, normalizedPath).replaceAll("\\", "/") || "."
        : EXTERNAL_PATH;
    sanitizedCommand = sanitizedCommand.replaceAll(token, () => safePath);
  }

  const unclassifiedCommand = tokens.reduce(
    (value, token) => value.replaceAll(token, ""),
    command,
  );
  const unclassifiedPaths = [...unclassifiedCommand.matchAll(ABSOLUTE_PATH_PATTERN)]
    .map((match) => match[2] ?? "");
  workspaceLocal = unclassifiedPaths.length === 0 ? workspaceLocal : false;
  for (const path of unclassifiedPaths) {
    const normalizedPath = normalizePathForComparison(path, cwd ?? "/");
    hardRuleHit = hardRuleHit || isSensitivePath(normalizedPath, homedir());
  }
  sanitizedCommand = sanitizedCommand.replace(
    ABSOLUTE_PATH_PATTERN,
    (_match, prefix: string, path: string) => prefix + (isSensitivePath(normalizePathForComparison(path, cwd ?? "/"), homedir()) ? SENSITIVE_PATH : PATH),
  );

  const hasNetworkTarget = extractAllNetworkTargets(command).length > 0;
  workspaceLocal = workspaceLocal && !hasNetworkTarget;

  return { command: sanitizedCommand, workspaceLocal, hardRuleHit };
}
