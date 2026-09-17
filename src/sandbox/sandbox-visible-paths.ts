import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { realpathSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, resolve } from "node:path";

import { EXTENSION_ROOT } from "../extension-config.js";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";
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
  "/run/systemd",
  "/var/select",
  "/private/var/select",
];

const KNOWN_HOME_VISIBLE_PATHS: string[] = [
  ".local/bin",
  ".local/lib",
  ".cargo/bin",
  ".bun/bin",
];
const UV_HOME_VISIBLE_PATHS: string[] = [".local/share/uv", ".cache/uv"];
const DIRECT_UV_COMMAND_PATTERN = /^\s*(?:(?:env|command|exec|sudo)\s+)*(?:\S*\/)?uvx?(?!\s*\(\s*\))(?=$|\s)/;

const KNOWN_HOME_FILES: string[] = [];
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
  return absPath === prefix || absPath.startsWith(prefix + "/");
}

function homeVisiblePathsForCommand(
  command: string | undefined,
  commandUsesUv: boolean | undefined,
): string[] {
  const includeUvRoots = commandUsesUv ?? (
    command === undefined ||
    (!/\\\r?\n/.test(command) && DIRECT_UV_COMMAND_PATTERN.test(command))
  );
  return includeUvRoots
    ? [...KNOWN_HOME_VISIBLE_PATHS, ...UV_HOME_VISIBLE_PATHS]
    : KNOWN_HOME_VISIBLE_PATHS;
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

  const homeVisiblePaths = homeVisiblePathsForCommand(context.command, context.commandUsesUv).map((relPath) =>
    canonicalPath(resolve(home, relPath)),
  );
  const homeFiles = KNOWN_HOME_FILES.map((relPath) => canonicalPath(resolve(home, relPath)));
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

  const homeVisiblePaths = homeVisiblePathsForCommand(context.command, context.commandUsesUv).map((relPath) =>
    canonicalPath(resolve(home, relPath)),
  );
  const homeFiles = KNOWN_HOME_FILES.map((relPath) => canonicalPath(resolve(home, relPath)));
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
  const homeVisiblePaths = await canonicalizeVisiblePaths(
    homeVisiblePathsForCommand(context.command, context.commandUsesUv).map((relativePath) => resolve(homedir(), relativePath)),
    deadline,
    durationMs,
  );
  const homeFiles = await canonicalizeVisiblePaths(
    KNOWN_HOME_FILES.map((relativePath) => resolve(homedir(), relativePath)),
    deadline,
    durationMs,
  );
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
