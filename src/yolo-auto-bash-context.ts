import { homedir } from "node:os";
import { relative } from "node:path";

import { resolve } from "node:path";

import { splitBashSegments } from "./bash-segments.js";
import { extractAllNetworkTargets } from "./network/domain-extractor.js";
import { isPathWithinCanonicalWorkingDirectory, normalizePathForComparison } from "./path-utils.js";
import { isSensitivePath } from "./yolo-auto-sensitive-paths.js";

const ABSOLUTE_PATH_PATTERN = /(^|[\s"'=\x3e])((?:~\/|\/)[^\s"'\x3c\x3e;\x26|]+)/g;
const OPEN_ANGLE = String.fromCharCode(60);
const CLOSE_ANGLE = String.fromCharCode(62);
const SENSITIVE_PATH = OPEN_ANGLE + "sensitive-path" + CLOSE_ANGLE;
const EXTERNAL_PATH = OPEN_ANGLE + "external-path" + CLOSE_ANGLE;
const PATH = OPEN_ANGLE + "path" + CLOSE_ANGLE;
/** Output sinks that neither read nor write workspace data. */
const DISCARD_DEVICES = new Set(["/dev/null", "/dev/stdout", "/dev/stderr"]);

export interface YoloAutoBashContext {
  command: string;
  workspaceLocal: boolean;
  hardRuleHit: boolean;
}

const CD_SEGMENT = new RegExp("^cd(?:\\s+(\\S+))?\\s*$");
const UNRESOLVABLE_CD = new RegExp("^[-~$]");

/** `cd` with no slash (`cd ..`, bare `cd`, `cd -`) escapes path extraction; check it directly. */
function cdLeavesWorkspace(command: string, cwd: string | undefined): boolean {
  if (!cwd) return true;
  let dir = cwd;
  for (const segment of splitBashSegments(command) ?? []) {
    const cd = segment.match(CD_SEGMENT);
    if (!cd) continue;
    const target = cd[1];
    if (!target || UNRESOLVABLE_CD.test(target)) return true;
    dir = resolve(dir, target);
    if (!isPathWithinCanonicalWorkingDirectory(dir, cwd)) return true;
  }
  return false;
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
  const tokens = [...new Set(pathTokens)]
    .filter((token) => token && !DISCARD_DEVICES.has(token))
    .sort((left, right) => right.length - left.length);

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
    .map((match) => match[2] ?? "")
    .filter((path) => !DISCARD_DEVICES.has(path));
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
  workspaceLocal = workspaceLocal && !hasNetworkTarget && !cdLeavesWorkspace(command, cwd);

  return { command: sanitizedCommand, workspaceLocal, hardRuleHit };
}
