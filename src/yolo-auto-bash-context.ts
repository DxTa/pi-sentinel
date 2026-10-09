import { homedir } from "node:os";
import { relative } from "node:path";

import { resolve } from "node:path";

import { bashInnerCommands } from "./bash-segments.js";
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
  /* Redacted inner commands; empty when the command cannot be split. */
  units: string[];
  /* The inner commands cannot all be read statically. */
  opaque: boolean;
}

const CD_COMMAND = new RegExp("^cd(?:\\s+(\\S+))?(?:\\s|$)");
const UNRESOLVABLE_CD = new RegExp("^[-~$]");

/** `cd` with no slash (`cd ..`, bare `cd`, `cd -`) escapes path extraction; check it directly. */
function cdLeavesWorkspace(command: string, cwd: string | undefined): boolean {
  if (!cwd) return true;
  let dir = cwd;
  const inner = bashInnerCommands(command);
  if (inner === null) return true;
  for (const part of inner.commands) {
    const cd = part.match(CD_COMMAND);
    if (!cd) continue;
    const target = cd[1];
    if (!target || UNRESOLVABLE_CD.test(target)) return true;
    dir = resolve(dir, target);
    if (!isPathWithinCanonicalWorkingDirectory(dir, cwd)) return true;
    // A child shell's `cd` may not carry over, so the target must also stay inside when read from the start.
    if (inner.scoped && !isPathWithinCanonicalWorkingDirectory(resolve(cwd, target), cwd)) return true;
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
  const replacements: Array<[token: string, safePath: string]> = [];
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
    replacements.push([token, safePath]);
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
  const redact = (text: string): string =>
    replacements
      .reduce((value, [token, safePath]) => value.replaceAll(token, () => safePath), text)
      .replace(
        ABSOLUTE_PATH_PATTERN,
        (_match, prefix: string, path: string) => prefix + (isSensitivePath(normalizePathForComparison(path, cwd ?? "/"), homedir()) ? SENSITIVE_PATH : PATH),
      );

  const hasNetworkTarget = extractAllNetworkTargets(command).length > 0;
  workspaceLocal = workspaceLocal && !hasNetworkTarget && !cdLeavesWorkspace(command, cwd);

  const inner = bashInnerCommands(command);
  return {
    command: redact(command),
    workspaceLocal,
    hardRuleHit,
    units: inner ? inner.commands.map(redact) : [],
    opaque: inner === null || inner.opaque,
  };
}
