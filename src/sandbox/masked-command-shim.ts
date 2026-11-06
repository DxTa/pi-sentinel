import { execFile, execFileSync } from "node:child_process";
import { existsSync, lstatSync, statSync } from "node:fs";
import { lstat, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";

import type { SandboxProfile } from "./types.js";
import { canonicalPath, normalizeMacPrivatePath } from "./sandbox-visible-paths.js";
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

/** A scan root whose masked-file scan failed; the caller must approve it before the command runs. */
export interface UnscannedRoot {
  root: string;
  reason: string;
}

export interface MaskedCommandShimPlan {
  /** Concrete files that get placeholder UX through reader shims. */
  maskedFilePaths: string[];
  /** Concrete files denied by SRT regardless of shim coverage. */
  maskedDenyPaths: string[];
  shimCommands: string[];
  /** Roots whose scan failed (timeout, budget, unreadable entries); empty when every root was scanned. */
  unscannedRoots: UnscannedRoot[];
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
const FIND_BINARY = "/usr/bin/find";
const MAX_FIND_OUTPUT_BYTES = 64 * 1024 * 1024;

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

const ALWAYS_READABLE_HOME_FILES = [".gitconfig", ".gitignore"] as const;

function isAlwaysReadableHomeFile(root: string): boolean {
  const resolved = resolve(root);
  return ALWAYS_READABLE_HOME_FILES.some((relativePath) =>
    resolved === resolve(homedir(), relativePath),
  );
}

function dedupe(values: string[]): string[] {
  const seen = new Set<string>();
  return values.flatMap((value) => {
    const resolved = resolve(value);
    const key = normalizeMacPrivatePath(canonicalPath(resolved));
    if (seen.has(key)) return [];
    seen.add(key);
    return [resolved];
  });
}

function dedupeMaskedPaths(values: string[]): string[] {
  const paths = values.flatMap((value) => {
    const resolved = resolve(value);
    const canonical = canonicalPath(resolved);
    return normalizeMacPrivatePath(canonical) === normalizeMacPrivatePath(resolved)
      ? [resolved]
      : [resolved, normalizeMacPrivatePath(canonical)];
  });
  return [...new Set(paths)];
}

function getMaskedPatterns(profile: SandboxProfile): string[] {
  return profile.maskedPaths?.length ? profile.maskedPaths : DEFAULT_MASKED_PATTERNS;
}

function isWithinScanDepth(root: string, candidate: string, maxDepth: number): boolean {
  const relativePath = relative(normalizeMacPrivatePath(root), normalizeMacPrivatePath(candidate));
  if (relativePath === ".") return true;
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`)) return false;
  return relativePath.split(sep).length <= maxDepth;
}

function rootsOverlap(left: string, right: string): boolean {
  return left === right || left.startsWith(`${right}${sep}`) || right.startsWith(`${left}${sep}`);
}

function getAbsoluteMaskedPatternPrefix(pattern: string): string | null {
  const expanded = pattern.startsWith("~" + sep)
    ? join(homedir(), pattern.slice(2))
    : pattern;
  if (expanded.startsWith(sep) === false) return null;
  const wildcardIndex = expanded.search(new RegExp("[?*]"));
  const lastSeparator = expanded.lastIndexOf(sep);
  if (wildcardIndex !== -1 && wildcardIndex < lastSeparator) return null;
  const prefix = wildcardIndex === -1
    ? dirname(expanded)
    : expanded.slice(0, wildcardIndex).replace(new RegExp(`${sep}$`), "");
  return canonicalPath(prefix);
}

/** Absolute `dir/**` masks: denied as one directory instead of enumerating every file inside. */
function wholeDirMask(pattern: string): string | null {
  const expanded = pattern.startsWith("~" + sep) ? join(homedir(), pattern.slice(2)) : pattern;
  const suffix = `${sep}**`;
  if (!expanded.startsWith(sep) || !expanded.endsWith(suffix)) return null;
  const dir = expanded.slice(0, -suffix.length);
  return /[?*[\]]/.test(dir) ? null : canonicalPath(dir);
}

function getWholeDirMasks(profile: SandboxProfile): string[] {
  return getMaskedPatterns(profile).flatMap((pattern) => wholeDirMask(pattern) ?? []);
}

function isWithinWholeDirMask(path: string, masks: string[]): boolean {
  const normalized = normalizeMacPrivatePath(resolve(path));
  return masks.some((mask) => {
    const normalizedMask = normalizeMacPrivatePath(mask);
    return normalized === normalizedMask || normalized.startsWith(`${normalizedMask}${sep}`);
  });
}

/** Whole-dir masks strictly inside root, expressed with root's own prefix for `find -path`. */
function getPrunePaths(profile: SandboxProfile, root: string): string[] {
  const normalizedRoot = normalizeMacPrivatePath(resolve(root));
  return getWholeDirMasks(profile).flatMap((mask) => {
    const normalizedMask = normalizeMacPrivatePath(mask);
    if (!normalizedMask.startsWith(`${normalizedRoot}${sep}`)) return [];
    return [join(root, relative(normalizedRoot, normalizedMask)).replace(/[?*[\]\\]/g, "\\$&")];
  });
}

/** Existing whole-dir masks visible from any scan root. */
function existingWholeDirDenyPaths(profile: SandboxProfile, scanRoots: string[]): string[] {
  return getWholeDirMasks(profile).filter((mask) =>
    scanRoots.some((root) => rootsOverlap(normalizeMacPrivatePath(resolve(root)), normalizeMacPrivatePath(mask)))
    && statSync(mask, { throwIfNoEntry: false })?.isDirectory() === true,
  );
}

function getFindNamePatterns(profile: SandboxProfile, root: string): string[] {
  const names = new Set<string>();
  for (const pattern of getMaskedPatterns(profile)) {
    if (wholeDirMask(pattern) !== null) continue;
    const expanded = pattern.startsWith("~" + sep)
      ? join(homedir(), pattern.slice(2))
      : pattern;
    if (expanded.startsWith(sep)) {
      const fixedPrefix = getAbsoluteMaskedPatternPrefix(pattern);
      const normalizedRoot = normalizeMacPrivatePath(resolve(root));
      const normalizedPrefix = fixedPrefix === null ? null : normalizeMacPrivatePath(resolve(fixedPrefix));
      if (normalizedPrefix !== null && rootsOverlap(normalizedRoot, normalizedPrefix) === false) continue;
    }
    const name = expanded.slice(expanded.lastIndexOf(sep) + 1) || "*";
    names.add((name === "**" ? "*" : name).replace(new RegExp("[\\[\\]]", "g"), "\\$&"));
  }
  return [...names];
}

function buildFindArgs(root: string, namePatterns: string[], maxDepth: number, prunePaths: string[] = []): string[] {
  const args = process.platform === "linux" ? [root, "-maxdepth", String(maxDepth)] : [root];
  if (prunePaths.length > 0) {
    args.push("(");
    prunePaths.forEach((prunePath, index) => {
      if (index > 0) args.push("-o");
      args.push("-path", prunePath);
    });
    args.push(")", "-prune", "-o");
  }
  args.push("(", "-type", "f", "-o", "-type", "l", ")");
  if (namePatterns.length > 0) {
    args.push("(");
    namePatterns.forEach((pattern, index) => {
      if (index > 0) args.push("-o");
      args.push("-name", pattern);
    });
    args.push(")");
  }
  args.push("-print0");
  return args;
}

function parseFindOutput(
  output: Buffer,
  root: string,
  profile: SandboxProfile,
  maxEntries: number,
  maxDepth: number,
  scanDeadline: number,
  maxScanDurationMs: number,
): string[] {
  if (output.length === 0) return [];
  if (output[output.length - 1] !== 0) {
    throw new Error(`Find file inventory returned incomplete output at ${root}`);
  }

  const patterns = getMaskedPatterns(profile);
  const results: string[] = [];
  for (const candidate of output.toString("utf8").split("\0")) {
    assertScanWithinBudget(scanDeadline, maxScanDurationMs, root);
    if (!candidate) continue;
    const resolvedCandidate = resolve(candidate);
    const comparisonCandidate = normalizeMacPrivatePath(resolvedCandidate);
    if (!isWithinScanDepth(root, comparisonCandidate, maxDepth) || !isPathMasked(comparisonCandidate, patterns)) continue;
    results.push(resolvedCandidate);
    if (results.length > maxEntries) {
      throw new Error(`Masked file scan exceeded ${maxEntries} entries at ${resolvedCandidate}`);
    }
  }
  return results;
}

export function isPermissionDeniedOnly(
  error: { code?: unknown; killed?: boolean; signal?: unknown },
  stderr: string | Buffer,
): boolean {
  if (error.code !== 1 || error.killed || error.signal) return false;
  const lines = String(stderr).split("\n").filter((line) => line.trim());
  return lines.length > 0 && lines.every((line) => line.startsWith("find: ") && line.endsWith(": Permission denied"));
}

function runFindSync(
  root: string,
  profile: SandboxProfile,
  maxEntries: number,
  maxDepth: number,
  scanDeadline: number,
  maxScanDurationMs: number,
): string[] {
  assertScanWithinBudget(scanDeadline, maxScanDurationMs, root);
  let output: Buffer;
  try {
    output = execFileSync(FIND_BINARY, buildFindArgs(root, getFindNamePatterns(profile, root), maxDepth, getPrunePaths(profile, root)), {
      encoding: "buffer",
      maxBuffer: MAX_FIND_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: Math.max(1, scanDeadline - Date.now()),
    });
  } catch (error) {
    // Like the async scan: unreadable directories (exit 1, only "Permission denied" lines) do not fail the scan.
    const failure = error as { status?: number; killed?: boolean; signal?: unknown; stdout?: Buffer; stderr?: Buffer };
    if (!isPermissionDeniedOnly({ code: failure.status, killed: failure.killed, signal: failure.signal }, failure.stderr ?? "")) throw error;
    output = failure.stdout ?? Buffer.alloc(0);
  }
  assertScanWithinBudget(scanDeadline, maxScanDurationMs, root);
  return parseFindOutput(output, root, profile, maxEntries, maxDepth, scanDeadline, maxScanDurationMs);
}

function expandMaskedScanRoots(scanRoots: string[], profile: SandboxProfile): string[] {
  const roots = normalizeScanRoots(scanRoots);
  const additions: string[] = [];
  for (const pattern of getMaskedPatterns(profile)) {
    if (wholeDirMask(pattern) !== null) continue;
    const fixedPrefix = getAbsoluteMaskedPatternPrefix(pattern);
    if (fixedPrefix === null) continue;
    if (roots.some((root) => fixedPrefix.startsWith(`${resolve(root)}${sep}`))) {
      additions.push(fixedPrefix);
    }
  }
  const masks = getWholeDirMasks(profile);
  return dedupe([...roots, ...additions])
    .filter(shouldScanRoot)
    .filter((root) => !isWithinWholeDirMask(root, masks));
}

function shouldScanRoot(root: string): boolean {
  const resolved = normalizeMacPrivatePath(resolve(root));
  return existsSync(resolved) && isScannableRoot(resolved);
}

function normalizeScanRoots(roots: string[]): string[] {
  const normalized = dedupe(roots).filter(shouldScanRoot);
  return normalized.filter((root) => {
    const normalizedRoot = normalizeMacPrivatePath(root);
    return !normalized.some((ancestor) => {
      const normalizedAncestor = normalizeMacPrivatePath(ancestor);
      return normalizedAncestor !== normalizedRoot && normalizedRoot.startsWith(`${normalizedAncestor}/`);
    });
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
  if (isAlwaysReadableHomeFile(root)) return [];
  const rootStat = statSync(root);
  if (rootStat.isDirectory() === false) {
    if (rootStat.isFile()) {
      if (isPathMasked(root, getMaskedPatterns(profile))) return [root];
    }
    return [];
  }
  return runFindSync(root, profile, maxEntries, maxDepth, scanDeadline, maxScanDurationMs);
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
    : expandMaskedScanRoots([
        cwd,
        ...(options.scanRoots ?? []),
      ], profile);
  // Mask classification is security-critical. A partial scan cannot prove that
  // an allowed root contains no protected files, so fail closed instead of
  // relying on command-text detection or an unsupported pattern-only fallback.
  const scanDeadline = Date.now() + maxScanDurationMs;
  const scannedMaskedFiles: string[] = [];
  const unscannedRoots: UnscannedRoot[] = [];
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
      unscannedRoots.push({ root, reason: String(scanError).replace(/^Error: /, "") });
    }
  }

  const wholeDirDenyPaths = options.skipWorkspaceScan
    ? []
    : existingWholeDirDenyPaths(profile, [cwd, ...(options.scanRoots ?? [])]);
  const maskedDenyPaths = [...dedupeMaskedPaths([
    ...scannedMaskedFiles,
    ...maskedFilePaths,
  ]).filter((path) => {
    try {
      return statSync(path).isFile() || lstatSync(path).isSymbolicLink();
    } catch {
      return false;
    }
  }), ...wholeDirDenyPaths];

  if (maskedFilePaths.length === 0) {
    return { maskedFilePaths: [], maskedDenyPaths, shimCommands: [], unscannedRoots };
  }

  // Prototype scope: only provide nicer `(masked)` content for common direct reads.
  // SRT still denies real masked paths, so bypasses fail closed instead of leaking.
  const supportedReaders = ["cat", "head", "tail", "grep", "rg"];
  const shimCommands = supportedReaders.filter((reader) =>
    new RegExp(`(^|[\\s;&|()])${reader}([\\s;&|()]|$)`).test(command),
  );

  return { maskedFilePaths, maskedDenyPaths, shimCommands, unscannedRoots };
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
    : expandMaskedScanRoots([
        cwd,
        ...(options.scanRoots ?? []),
      ], profile).filter(isScannableRoot);
  const scannedMaskedFiles: string[] = [];
  const unscannedRoots: UnscannedRoot[] = [];

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
      unscannedRoots.push({ root, reason: String(scanError).replace(/^Error: /, "") });
    }
  }

  const wholeDirDenyPaths = options.skipWorkspaceScan
    ? []
    : existingWholeDirDenyPaths(profile, [cwd, ...(options.scanRoots ?? [])]);
  const maskedDenyPaths = dedupeMaskedPaths([...scannedMaskedFiles, ...maskedFilePaths]);
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

  existingMaskedDenyPaths.push(...wholeDirDenyPaths);

  if (maskedFilePaths.length === 0) {
    return { maskedFilePaths: [], maskedDenyPaths: existingMaskedDenyPaths, shimCommands: [], unscannedRoots };
  }

  const supportedReaders = ["cat", "head", "tail", "grep", "rg"];
  const shimCommands = supportedReaders.filter((reader) =>
    new RegExp(`(^|[\\s;&|()])${reader}([\\s;&|()]|$)`).test(command),
  );
  return { maskedFilePaths, maskedDenyPaths: existingMaskedDenyPaths, shimCommands, unscannedRoots };
}

function isScannableRoot(root: string): boolean {
  const resolved = resolve(root);
  if (ASYNC_UNSCANNABLE_EXACT_ROOTS.includes(resolved)) return false;
  return !NON_SECRET_SYSTEM_ROOTS.some((systemRoot) => {
    const normalized = resolve(systemRoot);
    return resolved === normalized || resolved.startsWith(normalized + "/");
  });
}

async function runFindAsync(
  root: string,
  profile: SandboxProfile,
  maxEntries: number,
  maxDepth: number,
  scanDeadline: number,
  maxScanDurationMs: number,
): Promise<string[]> {
  assertScanWithinBudget(scanDeadline, maxScanDurationMs, root);
  const output = await new Promise<Buffer>((resolveOutput, reject) => {
    execFile(
      FIND_BINARY,
      buildFindArgs(root, getFindNamePatterns(profile, root), maxDepth, getPrunePaths(profile, root)),
      {
        encoding: "buffer",
        maxBuffer: MAX_FIND_OUTPUT_BYTES,
        timeout: Math.max(1, scanDeadline - Date.now()),
      },
      (error, stdout, stderr) => {
        if (error && !isPermissionDeniedOnly(error, stderr)) {
          reject(error);
          return;
        }
        resolveOutput(Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout ?? ""));
      },
    );
  });
  assertScanWithinBudget(scanDeadline, maxScanDurationMs, root);
  return parseFindOutput(output, root, profile, maxEntries, maxDepth, scanDeadline, maxScanDurationMs);
}

async function collectConcreteMaskedFilesAsync(
  root: string,
  profile: SandboxProfile,
  maxEntries: number,
  maxDepth: number,
  scanDeadline: number,
  maxScanDurationMs: number,
): Promise<string[]> {
  if (isAlwaysReadableHomeFile(root)) return [];
  const rootStat = await awaitWithinScanBudget(
    stat(root),
    scanDeadline,
    maxScanDurationMs,
    root,
  );
  if (rootStat.isDirectory() === false) {
    if (rootStat.isFile()) {
      if (isPathMasked(root, getMaskedPatterns(profile))) return [root];
    }
    return [];
  }
  return runFindAsync(root, profile, maxEntries, maxDepth, scanDeadline, maxScanDurationMs);
}
