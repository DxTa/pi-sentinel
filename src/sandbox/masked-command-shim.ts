import { existsSync, lstatSync, readdirSync, realpathSync, statSync } from "node:fs";
import { lstat, readdir, realpath, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import type { SandboxProfile } from "./types.js";
import {
  assertScanWithinBudget,
  awaitWithinScanBudget,
  DEFAULT_SCAN_DURATION_MS,
  isScanBudgetExceeded,
} from "./scan-budget.js";
import {
  DEFAULT_MASKED_PATTERNS,
  detectMaskedFileAccess,
  isPathMasked,
} from "./masked-file-gate.js";

export interface MaskedCommandShimPlanOptions {
  /** Roots whose contents are readable in runtime and therefore must be masked-denied. */
  scanRoots?: string[];
  /** Skip broad root enumeration for a narrowly trusted command. */
  skipWorkspaceScan?: boolean;
  maxEntries?: number;
  maxDepth?: number;
  maxScanDurationMs?: number;
}

export interface MaskedCommandShimPlan {
  /** Concrete files that get placeholder UX through reader shims. */
  maskedFilePaths: string[];
  /** Concrete files denied by SRT regardless of shim coverage. */
  maskedDenyPaths: string[];
  shimCommands: string[];
}

const NON_SECRET_SYSTEM_ROOTS = [
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/System",
  "/Library",
  "/Applications",
  "/opt",
  "/nix",
  "/Volumes",
  "/dev",
  "/proc",
  "/etc",
  "/run",
  "/var/select",
  "/private/var/select",
];

const DEFAULT_MAX_SCAN_ENTRIES = 50_000;
const DEFAULT_MAX_SCAN_DEPTH = 40;
const DEFAULT_MAX_SCAN_DURATION_MS = DEFAULT_SCAN_DURATION_MS;

/**
 * Absolute path prefixes whose subtrees are huge non-secret runtime caches.
 * They are runtime read-allow paths but hold no masked-secret patterns, so
 * scanning them is wasted work that can blow the entry cap and block commands.
 */
const PRUNE_PATH_PREFIXES: string[] = (() => {
  const home = homedir();
  return [
    resolve(home, ".local/share/uv"),
    resolve(home, ".cache/uv"),
  ];
})();

// SRT excludes temporary roots from its runtime read allowlist. Scanning them
// for concrete masks only adds unbounded host state to every invocation.
const tempRoot = resolve(tmpdir());
const tempRootAlias = tempRoot.startsWith("/private/")
  ? tempRoot.slice("/private".length)
  : `/private${tempRoot}`;
const ASYNC_UNSCANNABLE_EXACT_ROOTS = [
  "/tmp",
  "/private/tmp",
  tempRoot,
  tempRootAlias,
];

function isUnderPrunePrefix(absPath: string): boolean {
  return PRUNE_PATH_PREFIXES.some(
    (prefix) => absPath === prefix || absPath.startsWith(prefix + "/"),
  );
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => resolve(value)))];
}

function getMaskedPatterns(profile: SandboxProfile): string[] {
  return profile.maskedPaths?.length ? profile.maskedPaths : DEFAULT_MASKED_PATTERNS;
}

function expandHomePatternRoot(pattern: string): string | null {
  if (!pattern.startsWith("~/")) return null;
  const expanded = resolve(homedir(), pattern.slice(2));
  const wildcardIndex = expanded.search(/[*?\[]/);
  if (wildcardIndex === -1) return expanded;
  const prefix = expanded.slice(0, wildcardIndex);
  const slashIndex = prefix.lastIndexOf("/");
  return slashIndex > 0 ? prefix.slice(0, slashIndex) : dirname(prefix);
}

function getPatternScanRoots(profile: SandboxProfile): string[] {
  return getMaskedPatterns(profile)
    .map(expandHomePatternRoot)
    .filter((root): root is string => root !== null);
}

function shouldScanRoot(root: string): boolean {
  const resolved = resolve(root);
  if (!existsSync(resolved)) return false;
  return !NON_SECRET_SYSTEM_ROOTS.some((systemRoot) => {
    const normalized = resolve(systemRoot);
    return resolved === normalized || resolved.startsWith(normalized + "/");
  });
}


function collectConcreteMaskedFiles(
  root: string,
  profile: SandboxProfile,
  maxEntries: number,
  maxDepth: number,
  scanDeadline: number,
  maxScanDurationMs: number,
): string[] {
  const patterns = getMaskedPatterns(profile);
  const results: string[] = [];
  const stack: Array<{ path: string; depth: number }> = [{ path: resolve(root), depth: 0 }];
  const visitedDirs = new Set<string>();
  let entriesSeen = 0;

  while (stack.length > 0) {
    const current = stack.pop()!;
    assertScanWithinBudget(scanDeadline, maxScanDurationMs, current.path);

    // Prune huge non-secret runtime state subtrees. These are runtime
    // read-allow paths but contain no masked-secret patterns and can exceed
    // the scan cap, blocking every bash call.
    if (isUnderPrunePrefix(current.path)) continue;

    entriesSeen += 1;
    if (entriesSeen > maxEntries) {
      throw new Error(`Masked file scan exceeded ${maxEntries} entries at ${current.path}`);
    }
    if (current.depth > maxDepth) continue;

    let stat;
    try {
      stat = lstatSync(current.path);
    } catch {
      continue;
    }

    if (stat.isSymbolicLink()) {
      if (isPathMasked(current.path, patterns)) results.push(current.path);
      continue;
    }

    if (stat.isFile()) {
      if (isPathMasked(current.path, patterns)) results.push(current.path);
      continue;
    }
    if (!stat.isDirectory()) continue;

    let realPath;
    try {
      realPath = realpathSync(current.path);
    } catch {
      continue;
    }
    if (visitedDirs.has(realPath)) continue;
    visitedDirs.add(realPath);

    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(current.path, { withFileTypes: true });
    } catch {
      continue;
    }

    // Skip vendored/build/cache/junk subtrees during the masked-file scan.
    // These dirs contain no secret patterns (.env/.pem/.key/ssh/...), but they
    // balloon the entry count past the scan cap (e.g. YouCompleteMe rust-analyzer
    // HTML docs = 50k+ files), which throws and blocks every bash call.
    const PRUNE_DIR_NAMES = new Set([
      ".git",
      "node_modules",
      ".venv",
      "venv",
      "__pycache__",
      ".mypy_cache",
      ".pytest_cache",
      ".ruff_cache",
      ".cache",
      ".turbo",
      "dist",
      "build",
      "target",
      "site-packages",
      "vim_runtime",
    ]);

    for (const entry of entries) {
      assertScanWithinBudget(scanDeadline, maxScanDurationMs, current.path);
      if (entry.isDirectory() && PRUNE_DIR_NAMES.has(entry.name)) continue;
      stack.push({ path: join(current.path, entry.name), depth: current.depth + 1 });
    }
  }

  return results;
}

export function buildMaskedCommandShimPlan(
  command: string,
  profile: SandboxProfile,
  cwd: string,
  options: MaskedCommandShimPlanOptions = {},
): MaskedCommandShimPlan {
  const maskedFilePaths = detectMaskedFileAccess(command, profile, cwd);
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_SCAN_ENTRIES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_SCAN_DEPTH;
  const maxScanDurationMs = options.maxScanDurationMs ?? DEFAULT_MAX_SCAN_DURATION_MS;
  const scanRoots = options.skipWorkspaceScan
    ? []
    : dedupe([
        cwd,
        ...(options.scanRoots ?? []),
        ...getPatternScanRoots(profile),
      ]).filter(shouldScanRoot);
  // Mask classification is security-critical. A partial scan cannot prove that
  // an allowed root contains no protected files, so fail closed instead of
  // relying on command-text detection or an unsupported pattern-only fallback.
  const scanDeadline = Date.now() + maxScanDurationMs;
  const scannedMaskedFiles: string[] = [];
  for (const root of scanRoots) {
    try {
      scannedMaskedFiles.push(
        ...collectConcreteMaskedFiles(
          root,
          profile,
          maxEntries,
          maxDepth,
          scanDeadline,
          maxScanDurationMs,
        ),
      );
    } catch (scanError) {
      const reason = String(scanError).replace(/^Error: /, "");
      throw new Error(`Masked file scan failed for ${root}: ${reason}`);
    }
  }

  const maskedDenyPaths = dedupe([
    ...scannedMaskedFiles,
    ...maskedFilePaths,
  ]).filter((path) => {
    try {
      return statSync(path).isFile() || lstatSync(path).isSymbolicLink();
    } catch {
      return false;
    }
  });

  if (maskedFilePaths.length === 0) {
    return { maskedFilePaths: [], maskedDenyPaths, shimCommands: [] };
  }

  // Prototype scope: only provide nicer `(masked)` content for common direct reads.
  // SRT still denies real masked paths, so bypasses fail closed instead of leaking.
  const supportedReaders = ["cat", "head", "tail", "grep", "rg"];
  const shimCommands = supportedReaders.filter((reader) =>
    new RegExp(`(^|[\\s;&|()])${reader}([\\s;&|()]|$)`).test(command),
  );

  return { maskedFilePaths, maskedDenyPaths, shimCommands };
}

export async function buildMaskedCommandShimPlanAsync(
  command: string,
  profile: SandboxProfile,
  cwd: string,
  options: MaskedCommandShimPlanOptions & {
    deadline: number;
  },
): Promise<MaskedCommandShimPlan> {
  const maskedFilePaths = detectMaskedFileAccess(command, profile, cwd);
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_SCAN_ENTRIES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_SCAN_DEPTH;
  const maxScanDurationMs = options.maxScanDurationMs ?? DEFAULT_MAX_SCAN_DURATION_MS;
  const scanRoots = options.skipWorkspaceScan
    ? []
    : dedupe([
        cwd,
        ...(options.scanRoots ?? []),
        ...getPatternScanRoots(profile),
      ]);
  const scannedMaskedFiles: string[] = [];

  for (const root of scanRoots) {
    if (!isScannableRoot(root)) continue;
    try {
      scannedMaskedFiles.push(
        ...(await collectConcreteMaskedFilesAsync(
          root,
          profile,
          maxEntries,
          maxDepth,
          options.deadline,
          maxScanDurationMs,
        )),
      );
    } catch (scanError) {
      const reason = String(scanError).replace(/^Error: /, "");
      throw new Error(`Masked file scan failed for ${root}: ${reason}`);
    }
  }

  const maskedDenyPaths = dedupe([...scannedMaskedFiles, ...maskedFilePaths]);
  const existingMaskedDenyPaths: string[] = [];
  for (const filePath of maskedDenyPaths) {
    try {
      const fileStat = await awaitWithinScanBudget(
        stat(filePath),
        options.deadline,
        maxScanDurationMs,
        filePath,
      );
      if (fileStat.isFile()) {
        existingMaskedDenyPaths.push(filePath);
        continue;
      }
    } catch (error) {
      if (isScanBudgetExceeded(error)) throw error;
    }
    try {
      const linkStat = await awaitWithinScanBudget(
        lstat(filePath),
        options.deadline,
        maxScanDurationMs,
        filePath,
      );
      if (linkStat.isSymbolicLink()) existingMaskedDenyPaths.push(filePath);
    } catch (error) {
      if (isScanBudgetExceeded(error)) throw error;
    }
  }

  if (maskedFilePaths.length === 0) {
    return { maskedFilePaths: [], maskedDenyPaths: existingMaskedDenyPaths, shimCommands: [] };
  }

  const supportedReaders = ["cat", "head", "tail", "grep", "rg"];
  const shimCommands = supportedReaders.filter((reader) =>
    new RegExp(`(^|[\\s;&|()])${reader}([\\s;&|()]|$)`).test(command),
  );
  return { maskedFilePaths, maskedDenyPaths: existingMaskedDenyPaths, shimCommands };
}

function isScannableRoot(root: string): boolean {
  const resolved = resolve(root);
  if (ASYNC_UNSCANNABLE_EXACT_ROOTS.includes(resolved)) return false;
  return !NON_SECRET_SYSTEM_ROOTS.some((systemRoot) => {
    const normalized = resolve(systemRoot);
    return resolved === normalized || resolved.startsWith(normalized + "/");
  });
}

async function collectConcreteMaskedFilesAsync(
  root: string,
  profile: SandboxProfile,
  maxEntries: number,
  maxDepth: number,
  scanDeadline: number,
  maxScanDurationMs: number,
): Promise<string[]> {
  const patterns = getMaskedPatterns(profile);
  const results: string[] = [];
  const stack: Array<{ path: string; depth: number }> = [{ path: resolve(root), depth: 0 }];
  const visitedDirs = new Set<string>();
  let entriesSeen = 0;

  while (stack.length > 0) {
    const current = stack.pop()!;
    assertScanWithinBudget(scanDeadline, maxScanDurationMs, current.path);
    if (isUnderPrunePrefix(current.path)) continue;
    entriesSeen += 1;
    if (entriesSeen > maxEntries) {
      throw new Error(`Masked file scan exceeded ${maxEntries} entries at ${current.path}`);
    }
    if (current.depth > maxDepth) continue;

    let fileStat;
    try {
      fileStat = await awaitWithinScanBudget(
        lstat(current.path),
        scanDeadline,
        maxScanDurationMs,
        current.path,
      );
    } catch (error) {
      if (isScanBudgetExceeded(error)) throw error;
      continue;
    }

    if (fileStat.isSymbolicLink()) {
      if (isPathMasked(current.path, patterns)) results.push(current.path);
      continue;
    }
    if (fileStat.isFile()) {
      if (isPathMasked(current.path, patterns)) results.push(current.path);
      continue;
    }
    if (!fileStat.isDirectory()) continue;

    let realPath: string;
    try {
      realPath = await awaitWithinScanBudget(
        realpath(current.path),
        scanDeadline,
        maxScanDurationMs,
        current.path,
      );
    } catch (error) {
      if (isScanBudgetExceeded(error)) throw error;
      continue;
    }
    if (visitedDirs.has(realPath)) continue;
    visitedDirs.add(realPath);

    let entries: import("node:fs").Dirent[];
    try {
      entries = await awaitWithinScanBudget(
        readdir(current.path, { withFileTypes: true }),
        scanDeadline,
        maxScanDurationMs,
        current.path,
      );
    } catch (error) {
      if (isScanBudgetExceeded(error)) throw error;
      continue;
    }

    const pruneDirNames = new Set([
      ".git",
      "node_modules",
      ".venv",
      "venv",
      "__pycache__",
      ".mypy_cache",
      ".pytest_cache",
      ".ruff_cache",
      ".cache",
      ".turbo",
      "dist",
      "build",
      "target",
      "site-packages",
      "vim_runtime",
    ]);
    for (const entry of entries) {
      assertScanWithinBudget(scanDeadline, maxScanDurationMs, current.path);
      if (entry.isDirectory() && pruneDirNames.has(entry.name)) continue;
      stack.push({ path: join(current.path, entry.name), depth: current.depth + 1 });
    }
  }

  return results;
}
