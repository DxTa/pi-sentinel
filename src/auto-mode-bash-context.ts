import { homedir } from "node:os";
import { relative } from "node:path";

import { resolve } from "node:path";

import { bashInnerCommands, splitBashSegments } from "./bash-segments.js";
import { extractAllNetworkTargets } from "./network/domain-extractor.js";
import { isPathWithinCanonicalWorkingDirectory, normalizePathForComparison } from "./path-utils.js";
import { isProtectedWriteTarget, isSensitivePath } from "./auto-mode-sensitive-paths.js";

const isHardRulePath = (path: string): boolean =>
  isSensitivePath(path, homedir()) || isProtectedWriteTarget(path, homedir());

const ABSOLUTE_PATH_PATTERN = /(^|[\s"'=\x3e])((?:~\/|\/)[^\s"'\x3c\x3e;\x26|]+)/g;
const OPEN_ANGLE = String.fromCharCode(60);
const CLOSE_ANGLE = String.fromCharCode(62);
const SENSITIVE_PATH = OPEN_ANGLE + "sensitive-path" + CLOSE_ANGLE;
const EXTERNAL_PATH = OPEN_ANGLE + "external-path" + CLOSE_ANGLE;
const PATH = OPEN_ANGLE + "path" + CLOSE_ANGLE;
/** Output sinks that neither read nor write workspace data. */
const DISCARD_DEVICES = new Set(["/dev/null", "/dev/stdout", "/dev/stderr"]);

export interface AutoModeBashContext {
  command: string;
  workspaceLocal: boolean;
  hardRuleHit: boolean;
  /* Redacted inner commands; empty when the command cannot be split. */
  units: string[];
  /* The inner commands cannot all be read statically. */
  opaque: boolean;
}

const SYSTEM_BIN_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];
const ENV_ASSIGNMENT = /^[A-Za-z_]\w*=/;

// A `..` spelling could reach outside the system dirs, so only normalized paths qualify.
const isSystemBinPath = (path: string): boolean =>
  resolve(path) === path && SYSTEM_BIN_DIRS.some((dir) => path === dir || path.startsWith(dir + "/"));

/** How often each system-bin path is used as the executable or a `PATH=` entry in one list of commands. */
function countSystemBinUses(parts: readonly string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const part of parts) {
    const words = part.trim().split(/\s+/);
    const used: string[] = [];
    while (words[0] && ENV_ASSIGNMENT.test(words[0])) {
      const [name, ...value] = words.shift()!.split("=");
      if (name === "PATH") used.push(...value.join("=").split(":"));
    }
    if (words[0]) used.push(words[0]);
    for (const path of used.filter(isSystemBinPath)) counts.set(path, (counts.get(path) ?? 0) + 1);
  }
  return counts;
}

/**
 * System-bin paths used only as the executable or as a `PATH=` entry; arguments never qualify.
 * Raw segments keep wrapper executables such as `/usr/bin/env`; inner commands expose the wrapped command.
 * A path that also appears elsewhere in the command (operand, redirect target) is not exempt.
 */
function systemBinUses(command: string): Map<string, number> {
  const raw = countSystemBinUses(splitBashSegments(command) ?? []);
  const inner = countSystemBinUses(bashInnerCommands(command)?.commands ?? []);
  for (const [path, count] of inner) raw.set(path, Math.max(raw.get(path) ?? 0, count));
  return raw;
}

const CD_COMMAND = new RegExp("^cd(?:\\s+(\\S+))?(?:\\s|$)");
const LOOPBACK_WITH_USERINFO = /:\/\/[^\s/]*@/;
const DIRECTORY_CHANGE = /(?:^|[\s;&|(){`$])(?:cd|pushd)(?:\s|$)/;
const LOOPBACK_TARGET = /^(?:localhost|127\.0\.0\.1|\[?::1\]?)(?::\d+)?$/;
const UNRESOLVABLE_CD = new RegExp("^[-~$]");

/** `cd` with no slash (`cd ..`, bare `cd`, `cd -`) escapes path extraction; check it directly. */
function cdLeavesWorkspace(command: string, cwd: string | undefined): boolean {
  if (!cwd) return true;
  let dir = cwd;
  const inner = bashInnerCommands(command);
  // An unsplittable command can only change directory through a literal cd or pushd word.
  if (inner === null) return DIRECTORY_CHANGE.test(command.replace(/['"\\]/g, ""));
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
export function buildAutoModeBashContext(
  command: string,
  pathTokens: readonly string[],
  cwd: string | undefined,
): AutoModeBashContext {
  let workspaceLocal = Boolean(cwd);
  let hardRuleHit = false;
  const replacements: Array<[token: string, safePath: string]> = [];
  const systemBins = systemBinUses(command);
  /** A `:`-joined value whose every entry is an allowed system bin or `$PATH`. */
  const isSystemBinOnly = (value: string): boolean =>
    value.split(":").every((entry) =>
      entry === "$PATH" || (systemBins.get(entry) ?? 0) >= command.split(entry).length - 1);
  const tokens = [...new Set(pathTokens)]
    .filter((token) => token && !DISCARD_DEVICES.has(token) && !isSystemBinOnly(token))
    .sort((left, right) => right.length - left.length);

  for (const token of tokens) {
    const dynamicPath = token.includes("$") || token.includes(String.fromCharCode(96));
    const networkAddress = token.includes("://");
    const normalizedPath = normalizePathForComparison(token, cwd ?? "/");
    const sensitivePath = dynamicPath ? true : networkAddress ? false : isHardRulePath(normalizedPath);
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
    .filter((path) => !DISCARD_DEVICES.has(path) && !isSystemBinOnly(path));
  workspaceLocal = unclassifiedPaths.length === 0 ? workspaceLocal : false;
  for (const path of unclassifiedPaths) {
    const normalizedPath = normalizePathForComparison(path, cwd ?? "/");
    hardRuleHit = hardRuleHit || isHardRulePath(normalizedPath);
  }
  const redact = (text: string): string =>
    replacements
      .reduce((value, [token, safePath]) => value.replaceAll(token, () => safePath), text)
      .replace(
        ABSOLUTE_PATH_PATTERN,
        (_match, prefix: string, path: string) => prefix + (isHardRulePath(normalizePathForComparison(path, cwd ?? "/")) ? SENSITIVE_PATH : PATH),
      );

  // A URL with userinfo (`http://127.0.0.1@host`) is read by curl as host `host`, not loopback.
  const hasNetworkTarget = LOOPBACK_WITH_USERINFO.test(command)
    || extractAllNetworkTargets(command).some((target) => !LOOPBACK_TARGET.test(target));
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
