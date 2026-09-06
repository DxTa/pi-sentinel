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
  ".local/share/uv",
  ".cache/uv",
  ".cargo/bin",
  ".bun/bin",
];

const KNOWN_HOME_FILES: string[] = [];
const require = createRequire(import.meta.url);

export interface SandboxVisibilityContext {
  repoRoot: string;
  cwd: string;
  profile: ResolvedSandboxProfile;
  config?: SandboxConfig;
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
  const bindPrefixes = [
    ...(context.config?.roBinds ?? []),
    ...(context.config?.rwBinds ?? []),
    ...(context.profile.roBinds ?? []),
    ...(context.profile.rwBinds ?? []),
  ].map((bind) => {
    const expanded = expandHomePath(bind);
    return canonicalPath(isAbsolute(expanded) ? expanded : resolve(repoRoot, expanded));
  });

  const homeVisiblePaths = KNOWN_HOME_VISIBLE_PATHS.map((relPath) =>
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
  const bindPrefixes = [
    ...(context.config?.roBinds ?? []),
    ...(context.config?.rwBinds ?? []),
    ...(context.profile.roBinds ?? []),
    ...(context.profile.rwBinds ?? []),
  ].map((bind) => {
    const expanded = expandHomePath(bind);
    return canonicalPath(isAbsolute(expanded) ? expanded : resolve(repoRoot, expanded));
  });

  const homeVisiblePaths = KNOWN_HOME_VISIBLE_PATHS.map((relPath) =>
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
  return [
    ...(context.config?.roBinds ?? []),
    ...(context.config?.rwBinds ?? []),
    ...(context.profile.roBinds ?? []),
    ...(context.profile.rwBinds ?? []),
  ].map((bind) => {
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
    KNOWN_HOME_VISIBLE_PATHS.map((relativePath) => resolve(homedir(), relativePath)),
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
