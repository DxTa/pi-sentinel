import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { lstatSync, realpathSync, statSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";

import { EXTENSION_ROOT } from "../extension-config.js";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";
import { isDockerCommand } from "./bypass-command.js";
import {
  assertScanWithinBudget,
  awaitWithinScanBudget,
  isScanBudgetExceeded,
} from "./scan-budget.js";

const KNOWN_SYSTEM_PREFIXES: string[] = [
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/System",
  "/Library",
  "/Applications",
  "/opt",
  "/dev",
  "/proc",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/hostname",
  "/etc/nsswitch.conf",
  "/etc/passwd",
  "/etc/group",
  "/etc/gitconfig",
  "/etc/gitattributes",
  "/etc/machine-id",
  "/etc/os-release",
  "/etc/ld.so.cache",
  "/etc/alternatives",
  "/etc/ssl",
  "/etc/pki",
  "/etc/ca-certificates",
  "/etc/protocols",
  "/etc/services",
  "/etc/shells",
  "/etc/localtime",
  "/var/db/timezone",
  "/run/systemd",
  "/var/select",
  "/private/var/select",
];

const DOCKER_HOME_VISIBLE_PATHS: string[] = [".docker"];
const KNOWN_HOME_VISIBLE_PATHS: string[] = [
  ".config",
  ".local/bin",
  ".local/lib",
  ".cargo/bin",
  ".bun/bin",
];
const UV_HOME_VISIBLE_PATHS: string[] = [".local/share/uv", ".cache/uv"];

/** UV package cache/data roots: readable for uv commands, but too large to masked-scan (hundreds of thousands of public package files). */
export function uvHomeRoots(): string[] {
  return UV_HOME_VISIBLE_PATHS.map((relativePath) => canonicalPath(resolve(homedir(), relativePath)));
}
const DIRECT_UV_COMMAND_PATTERN = /^\s*(?:(?:env|command|exec|sudo)\s+)*(?:\S*\/)?uvx?(?!\s*\(\s*\))(?=$|\s)/;

const KNOWN_HOME_FILES: string[] = [".gitconfig", ".gitignore"];
const require = createRequire(import.meta.url);

export interface SandboxVisibilityContext {
  repoRoot: string;
  cwd: string;
  /** Shell command controls whether command-specific tool roots are visible. */
  command?: string;
  /** Parsed command classification for async callers; omitted uses strict fallback. */
  commandUsesUv?: boolean;
  profile: ResolvedSandboxProfile;
  config?: SandboxConfig;
  resolvedBinds?: string[];
}

export function normalizeMacPrivatePath(value: string): string {
  if (process.platform !== "darwin") return value;
  if (value === "/private/var" || value.startsWith("/private/var/")) {
    return value.slice("/private".length);
  }
  return value;
}

export function canonicalPath(value: string): string {
  const resolved = resolve(value);
  let probe = resolved;
  const suffix: string[] = [];
  while (true) {
    try {
      const canonical = realpathSync.native(probe);
      return suffix.length === 0 ? canonical : resolve(canonical, ...suffix.reverse());
    } catch {
      const parent = dirname(probe);
      if (parent === probe) return resolved;
      suffix.push(basename(probe));
      probe = parent;
    }
  }
}

export async function canonicalPathWithinScanBudget(
  value: string,
  deadline: number,
  durationMs: number,
): Promise<string> {
  const resolved = resolve(value);
  let probe = resolved;
  const suffix: string[] = [];
  while (true) {
    try {
      const canonical = await awaitWithinScanBudget(
        realpath(probe),
        deadline,
        durationMs,
        probe,
      );
      return suffix.length === 0 ? canonical : resolve(canonical, ...suffix.reverse());
    } catch (error) {
      if (isScanBudgetExceeded(error)) throw error;
      const parent = dirname(probe);
      if (parent === probe) return resolved;
      suffix.push(basename(probe));
      probe = parent;
      assertScanWithinBudget(deadline, durationMs, probe);
    }
  }
}

function dedupeCanonical(values: string[]): string[] {
  return [...new Set(values.map(canonicalPath))];
}

export function expandHomePath(value: string): string {
  if (value.startsWith("~/")) return resolve(homedir(), value.slice(2));
  if (value === "~") return homedir();
  return value;
}

function pathMatchesPrefix(absPath: string, prefix: string): boolean {
  return absPath === prefix || absPath.startsWith(prefix + sep);
}

/**
 * Symlink nodes under $HOME on a logical path. macOS checks these nodes too, so allowing only the canonical target is not enough.
 * macOS only: Linux SRT binds each allowRead entry whole, so a link node would expose its target's siblings.
 * shortcut: home-only, so system aliases such as /var stay out of allowRead; upgrade if non-home symlinked paths need reads.
 */
export function homeSymlinkNodes(logicalPath: string): string[] {
  if (process.platform !== "darwin") return [];
  const home = homedir();
  const absPath = resolve(logicalPath);
  if (absPath === home || !pathMatchesPrefix(absPath, home)) return [];
  const nodes: string[] = [];
  let current = home;
  for (const part of relative(home, absPath).split(sep)) {
    current = resolve(current, part);
    try {
      if (lstatSync(current).isSymbolicLink()) nodes.push(current);
    } catch {
      break;
    }
  }
  return nodes;
}

/**
 * Symlinks on the way to the system read allow-list (`/etc` -> `/private/etc` on macOS). The sandbox must
 * resolve the link itself before it can read the target; the node grants no access to the target's contents.
 */
export function systemSymlinkNodes(): string[] {
  if (process.platform !== "darwin") return [];
  const nodes = new Set<string>();
  for (const prefix of KNOWN_SYSTEM_PREFIXES) {
    let current = "/";
    for (const part of prefix.split("/").filter(Boolean)) {
      current = resolve(current, part);
      try {
        if (lstatSync(current).isSymbolicLink()) nodes.add(current);
      } catch {
        break;
      }
    }
  }
  return [...nodes];
}

function isSafeHomePath(home: string, relativePath: string, candidate: string): boolean {
  if (candidate === home || !pathMatchesPrefix(candidate, home)) return false;
  try {
    if (lstatSync(resolve(home, relativePath)).isSymbolicLink()) return false;
    const stats = statSync(candidate);
    return relativePath === ".config" ? stats.isDirectory() : stats.isFile();
  } catch {
    return true;
  }
}

function canonicalHomeVisiblePath(home: string, relativePath: string): string | null {
  const candidate = canonicalPath(resolve(home, relativePath));
  return relativePath === ".config" && !isSafeHomePath(home, relativePath, candidate)
    ? null
    : candidate;
}

function canonicalHomeFile(home: string, relativePath: string): string | null {
  const candidate = canonicalPath(resolve(home, relativePath));
  return isSafeHomePath(home, relativePath, candidate) ? candidate : null;
}

/** Credential and agent folders stay hidden even when `$PATH` points into them. */
const HOME_PATH_EXCLUDED_ROOTS = [".ssh", ".aws", ".gnupg", ".kube", ".pi"];

/** `$PATH` entries inside the home directory, relative to it. The unsafe-path filter still applies to each. */
function homePathDirectories(): string[] {
  const home = homedir();
  return (process.env.PATH ?? "").split(":")
    .filter((entry) => isAbsolute(entry))
    .map((entry) => relative(home, entry))
    .filter((rel) => rel !== "" && !rel.startsWith("..") && !isAbsolute(rel))
    .filter((rel) => !HOME_PATH_EXCLUDED_ROOTS.includes(rel.split(sep)[0]!));
}

function homeVisiblePathsForCommand(
  command: string | undefined,
  commandUsesUv: boolean | undefined,
): string[] {
  const includeUvRoots = commandUsesUv ?? (
    command === undefined ||
    (!/\\\r?\n/.test(command) && DIRECT_UV_COMMAND_PATTERN.test(command))
  );
  // Tools installed under the home directory (Rancher Desktop, Homebrew-less setups) must be runnable.
  const pathDirs = homePathDirectories();
  const known = [...KNOWN_HOME_VISIBLE_PATHS, ...pathDirs];
  const paths = includeUvRoots ? [...known, ...UV_HOME_VISIBLE_PATHS] : known;
  return command !== undefined && isDockerCommand(command)
    ? [...paths, ...DOCKER_HOME_VISIBLE_PATHS]
    : paths;
}

function getRuntimePackageRoots(): string[] {
  const roots = [EXTENSION_ROOT];
  try {
    roots.push(dirname(require.resolve("@anthropic-ai/sandbox-runtime/package.json")));
  } catch {
    // The SRT backend reports a missing dependency separately.
  }
  return roots;
}

export function getSandboxTempPaths(): string[] {
  const values = new Set<string>();
  const envTmp = process.env.TMPDIR?.trim();
  if (envTmp) values.add(canonicalPath(envTmp));
  values.add(canonicalPath(tmpdir()));
  // Common user/tool overrides such as XDG_CACHE_HOME=/tmp/xdg-cache must work
  // on macOS too, where os.tmpdir() is usually /var/folders/... rather than /tmp.
  values.add(canonicalPath("/tmp"));
  values.add(canonicalPath("/private/tmp"));
  return [...values];
}

export function buildSandboxVisiblePaths(
  context: SandboxVisibilityContext,
): string[] {
  const repoRoot = canonicalPath(context.repoRoot);
  const cwd = canonicalPath(context.cwd);
  const home = canonicalPath(homedir());
  const bindPrefixes = bindPaths(context, repoRoot).map(canonicalPath);

  const homeVisiblePaths = homeVisiblePathsForCommand(context.command, context.commandUsesUv)
    .map((relPath) => canonicalHomeVisiblePath(home, relPath))
    .filter((value): value is string => value !== null);
  const homeFiles = KNOWN_HOME_FILES
    .map((relPath) => canonicalHomeFile(home, relPath))
    .filter((value): value is string => value !== null);
  const runtimePackageRoots = getRuntimePackageRoots().map(canonicalPath);

  return dedupeCanonical([
    repoRoot,
    cwd,
    ...bindPrefixes,
    ...KNOWN_SYSTEM_PREFIXES,
    ...homeVisiblePaths,
    ...homeFiles,
    ...runtimePackageRoots,
    ...getSandboxTempPaths(),
  ]);
}

export function buildSandboxRuntimeReadAllowPaths(
  context: SandboxVisibilityContext,
): string[] {
  const repoRoot = canonicalPath(context.repoRoot);
  const cwd = canonicalPath(context.cwd);
  const home = canonicalPath(homedir());
  const bindPrefixes = bindPaths(context, repoRoot).map(canonicalPath);

  const homeVisiblePaths = homeVisiblePathsForCommand(context.command, context.commandUsesUv)
    .map((relPath) => canonicalHomeVisiblePath(home, relPath))
    .filter((value): value is string => value !== null);
  const homeFiles = KNOWN_HOME_FILES
    .map((relPath) => canonicalHomeFile(home, relPath))
    .filter((value): value is string => value !== null);
  const runtimePackageRoots = getRuntimePackageRoots().map(canonicalPath);

  return dedupeCanonical([
    repoRoot,
    cwd,
    ...bindPrefixes,
    ...KNOWN_SYSTEM_PREFIXES,
    ...homeVisiblePaths,
    ...homeFiles,
    ...runtimePackageRoots,
    ...getSandboxTempPaths(),
  ]);
}

async function canonicalizeVisiblePaths(
  values: string[],
  deadline: number,
  durationMs: number,
): Promise<string[]> {
  return await Promise.all(values.map((value) =>
    canonicalPathWithinScanBudget(value, deadline, durationMs),
  ));
}

function bindPaths(context: SandboxVisibilityContext, repoRoot: string): string[] {
  const binds = context.resolvedBinds ?? [
    ...(context.config?.roBinds ?? []),
    ...(context.config?.rwBinds ?? []),
    ...(context.config?.infrastructureReadPaths ?? []),
    ...(context.profile.roBinds ?? []),
    ...(context.profile.rwBinds ?? []),
  ];
  return binds.map((bind) => {
    const expanded = expandHomePath(bind);
    return isAbsolute(expanded) ? expanded : resolve(repoRoot, expanded);
  });
}

export async function buildSandboxVisiblePathsWithinScanBudget(
  context: SandboxVisibilityContext,
  deadline: number,
  durationMs: number,
): Promise<string[]> {
  const repoRoot = await canonicalPathWithinScanBudget(context.repoRoot, deadline, durationMs);
  const cwd = await canonicalPathWithinScanBudget(context.cwd, deadline, durationMs);
  const bindPrefixes = await canonicalizeVisiblePaths(
    bindPaths(context, repoRoot),
    deadline,
    durationMs,
  );
  const home = await canonicalPathWithinScanBudget(homedir(), deadline, durationMs);
  const relativeHomeVisiblePaths = homeVisiblePathsForCommand(context.command, context.commandUsesUv);
  const homeVisiblePaths = (await canonicalizeVisiblePaths(
    relativeHomeVisiblePaths.map((relativePath) => resolve(homedir(), relativePath)),
    deadline,
    durationMs,
  )).filter((candidate, index) =>
    relativeHomeVisiblePaths[index] !== ".config" || isSafeHomePath(home, ".config", candidate),
  );
  const homeFiles = (await canonicalizeVisiblePaths(
    KNOWN_HOME_FILES.map((relativePath) => resolve(homedir(), relativePath)),
    deadline,
    durationMs,
  )).filter((candidate, index) => isSafeHomePath(home, KNOWN_HOME_FILES[index] ?? "", candidate));
  const runtimePackageRoots = await canonicalizeVisiblePaths(
    getRuntimePackageRoots(),
    deadline,
    durationMs,
  );

  return [...new Set([
    repoRoot,
    cwd,
    ...bindPrefixes,
    ...KNOWN_SYSTEM_PREFIXES,
    ...homeVisiblePaths,
    ...homeFiles,
    ...runtimePackageRoots,
    ...getSandboxTempPaths(),
  ])];
}

export function createSandboxVisibilityMatcher(
  context: SandboxVisibilityContext,
): (absPath: string) => boolean {
  const visiblePaths = buildSandboxVisiblePaths(context);

  return (candidate: string): boolean => {
    const absPath = canonicalPath(candidate);
    return visiblePaths.some((visiblePath) => pathMatchesPrefix(absPath, visiblePath));
  };
}
