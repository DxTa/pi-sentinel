import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { accessSync, constants, existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { mkdtemp, mkdir, open, readFile as readFileAsync, rename, rm, unlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { detectPhysicalHostArchitecture } from "./gondolin-architecture.js";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { UvPythonTarget } from "./gondolin-artifacts.js";
import {
  buildAssets as gondolinBuildAssets,
  getAssetVersion,
  getDefaultBuildConfig,
  getImageObjectDirectory,
  parseBuildConfig,
  serializeBuildConfig,
  importImageFromDirectory,
  loadAssetManifest,
  verifyAssets,
  type Architecture,
  type BuildConfig,
} from "@earendil-works/gondolin";

export const GONDOLIN_IMAGE_LOCK_SCHEMA = "pi-gondolin/image-lock@1" as const;
export const GONDOLIN_CONFIG_DIR = ".pi/gondolin";

const BUILD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/i;
const RUNTIME_PACKAGES = new Set([
  "nodejs",
  "npm",
  "bun",
  "python3",
  "uv",
  "rust",
  "cargo",
  "go",
  "ruby",
  "ruby-bundler",
  "openjdk17-jdk",
  "gcc",
  "g++",
  "make",
  "cmake",
  "php",
  "composer",
]);

const COMMON_PACKAGES = ["git", "ripgrep", "findutils", "coreutils", "e2fsprogs-extra"];
const REQUIRED_BUILD_COMMANDS = ["mke2fs", "lz4", "cpio", "find"] as const;
const DEFAULT_GONDOLIN_BUILD_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const execFileAsync = (command: string, args: readonly string[], options: Parameters<typeof execFile>[2]) =>
  new Promise<{ stdout: string; stderr: string }>((resolvePromise, reject) => {
    execFile(command, [...args], options, (error, stdout, stderr) => {
      if (error) {
        Object.assign(error, { stdout, stderr });
        reject(error);
        return;
      }
      resolvePromise({ stdout: String(stdout), stderr: String(stderr) });
    });
  });
const MAX_METADATA_BYTES = 64 * 1024;
const METADATA_DIRECTORY = [".pi", "gondolin"] as const;

const DETECTION_RULES = [
  { name: "node", files: ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", ".nvmrc"], packages: ["nodejs", "npm"] },
  { name: "python", files: ["pyproject.toml", "requirements.txt", "uv.lock", "poetry.lock", "Pipfile", "setup.py"], packages: ["python3", "uv"] },
  { name: "rust", files: ["Cargo.toml", "Cargo.lock"], packages: ["rust", "cargo"] },
  { name: "go", files: ["go.mod", "go.sum"], packages: ["go"] },
  { name: "ruby", files: ["Gemfile", "Gemfile.lock"], packages: ["ruby", "ruby-bundler"] },
  { name: "java", files: ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"], packages: ["openjdk17-jdk"] },
  { name: "c-cpp", files: ["CMakeLists.txt", "Makefile", "meson.build"], packages: ["gcc", "g++", "make", "cmake"] },
  { name: "php", files: ["composer.json", "composer.lock"], packages: ["php", "composer"] },
] as const;

export function resolveGondolinBuildPath(pathValue: string | undefined, workspaceRoot: string): string {
  const value = pathValue?.trim() || DEFAULT_GONDOLIN_BUILD_PATH;
  const root = resolve(workspaceRoot);
  const realRoot = realpathSync.native(root);
  const directories = value.split(":").filter(Boolean);
  if (directories.length === 0) throw new Error("Gondolin build PATH is empty.");
  for (const directory of directories) {
    if (!isAbsolute(directory)) throw new Error("Gondolin build PATH must contain absolute trusted directories.");
    const lexicalPath = resolve(directory);
    const relativePath = relative(root, lexicalPath);
    if (relativePath === "" || (!relativePath.startsWith(`..${sep}`) && relativePath !== "..")) {
      throw new Error("Gondolin build PATH must not include the workspace.");
    }
    try {
      const realDirectory = realpathSync.native(lexicalPath);
      const realRelativePath = relative(realRoot, realDirectory);
      if (realRelativePath === "" || (!realRelativePath.startsWith(`..${sep}`) && realRelativePath !== "..")) {
        throw new Error("Gondolin build PATH must not resolve into the workspace.");
      }
      const stats = statSync(realDirectory);
      if (!stats.isDirectory() || (stats.mode & 0o022) !== 0) {
        throw new Error("Gondolin build PATH may only contain non-world-writable directories.");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error("Gondolin build PATH directories must exist and be trusted.");
      }
      throw error;
    }
  }
  return directories.join(":");
}

export function missingGondolinBuildCommands(pathValue = process.env.PATH ?? ""): string[] {
  const directories = pathValue.split(":").filter(Boolean);
  return REQUIRED_BUILD_COMMANDS.filter((command) => !directories.some((directory) => {
    try {
      accessSync(join(directory, command), constants.X_OK);
      return true;
    } catch {
      return false;
    }
  }));
}

export interface GondolinWorkspacePlan {
  readonly detected: readonly string[];
  readonly metadataFiles: readonly string[];
  readonly config: BuildConfig;
  readonly planDigest: string;
  readonly configPath: string;
  readonly lockPath: string;
}

export interface GondolinImageLock {
  readonly schema: typeof GONDOLIN_IMAGE_LOCK_SCHEMA;
  readonly buildId: string;
  readonly manifestSha256: string;
  readonly configSha256: string;
  readonly arch: Architecture;
  readonly gondolinVersion: string;
}

function isWorkspaceDirectory(root: string): boolean {
  try {
    return statSync(root).isDirectory();
  } catch {
    return false;
  }
}

function canonicalWorkspaceRoot(workspaceRoot: string): string {
  try {
    return realpathSync.native(resolve(workspaceRoot));
  } catch {
    throw new Error("Gondolin workspace is unavailable.");
  }
}

async function ensureMetadataDirectory(workspaceRoot: string): Promise<string> {
  let current = canonicalWorkspaceRoot(workspaceRoot);
  for (const component of METADATA_DIRECTORY) {
    current = join(current, component);
    try {
      const stats = lstatSync(current);
      if (stats.isSymbolicLink() || !stats.isDirectory()) throw new Error("Gondolin metadata directory must not be a symlink or special file.");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(current);
      const stats = lstatSync(current);
      if (stats.isSymbolicLink() || !stats.isDirectory()) throw new Error("Gondolin metadata directory is unsafe.");
    }
  }
  return current;
}

function metadataFilePath(workspaceRoot: string, filename: string, allowMissing: boolean): string {
  let current = canonicalWorkspaceRoot(workspaceRoot);
  for (const component of METADATA_DIRECTORY) {
    current = join(current, component);
    const stats = lstatSync(current);
    if (stats.isSymbolicLink() || !stats.isDirectory()) throw new Error("Gondolin metadata directory is unsafe.");
  }
  const path = join(current, filename);
  try {
    const stats = lstatSync(path);
    if (stats.isSymbolicLink() || !stats.isFile()) throw new Error("Gondolin metadata file must be a regular file.");
    if (stats.size > MAX_METADATA_BYTES) throw new Error("Gondolin metadata file is too large.");
  } catch (error) {
    if (allowMissing && (error as NodeJS.ErrnoException).code === "ENOENT") return path;
    throw error;
  }
  return path;
}

function workspaceProfilePaths(workspaceRoot: string): { configPath: string; lockPath: string } | undefined {
  try {
    return {
      configPath: metadataFilePath(workspaceRoot, "build-config.json", true),
      lockPath: metadataFilePath(workspaceRoot, "image-lock.json", true),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function buildConfig(packages: readonly string[], architecture: Architecture): BuildConfig {
  const defaults = getDefaultBuildConfig();
  if (!defaults.alpine) throw new Error("Gondolin default Alpine config is unavailable.");
  const basePackages = (defaults.alpine.rootfsPackages ?? []).filter((entry) => !RUNTIME_PACKAGES.has(entry));
  return {
    ...defaults,
    arch: architecture,
    ...(defaults.oci ? { oci: { ...defaults.oci, platform: architecture === "aarch64" ? "linux/arm64" : "linux/amd64" } } : {}),
    alpine: {
      ...defaults.alpine,
      rootfsPackages: [...new Set([...basePackages, ...packages])],
    },
  };
}

function isSafeMetadataCandidate(path: string): boolean {
  try {
    const stats = lstatSync(path);
    return stats.isFile() && !stats.isSymbolicLink() && stats.size <= MAX_METADATA_BYTES;
  } catch {
    return false;
  }
}

/** Scan only root-level metadata names; never reads source or credential contents. */
export function planGondolinWorkspace(
  workspaceRoot: string,
  architecture: Architecture = detectPhysicalHostArchitecture(),
): GondolinWorkspacePlan {
  if (!isWorkspaceDirectory(workspaceRoot)) throw new Error("Gondolin workspace is unavailable.");

  const metadataFiles: string[] = [];
  const detected: string[] = [];
  const packages: string[] = [...COMMON_PACKAGES];
  for (const rule of DETECTION_RULES) {
    const found = rule.files.filter((file) => isSafeMetadataCandidate(join(workspaceRoot, file)));
    if (found.length === 0) continue;
    detected.push(rule.name);
    metadataFiles.push(...found);
    packages.push(...rule.packages);
    if (found.includes("pnpm-lock.yaml")) packages.push("pnpm");
    if (found.includes("yarn.lock")) packages.push("yarn");
    if (found.includes("bun.lock") || found.includes("bun.lockb")) packages.push("bun");
  }

  const config = buildConfig(packages, architecture);
  const planDigest = createHash("sha256").update(JSON.stringify({ detected, metadataFiles, config })).digest("hex");
  return {
    detected,
    metadataFiles,
    config,
    planDigest,
    configPath: join(workspaceRoot, GONDOLIN_CONFIG_DIR, "build-config.json"),
    lockPath: join(workspaceRoot, GONDOLIN_CONFIG_DIR, "image-lock.json"),
  };
}

function isArchitecture(value: unknown): value is Architecture {
  return value === "x86_64" || value === "aarch64";
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`Gondolin image lock ${name} is invalid.`);
  return value;
}

export function parseGondolinImageLock(value: unknown): GondolinImageLock {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Gondolin image lock is invalid.");
  }
  const record = value as Record<string, unknown>;
  const buildId = requiredString(record.buildId, "buildId");
  const manifestSha256 = requiredString(record.manifestSha256, "manifestSha256");
  const configSha256 = requiredString(record.configSha256, "configSha256");
  const gondolinVersion = requiredString(record.gondolinVersion, "gondolinVersion");
  if (record.schema !== GONDOLIN_IMAGE_LOCK_SCHEMA || !BUILD_ID.test(buildId)) {
    throw new Error("Gondolin image lock buildId or schema is invalid.");
  }
  if (!SHA256.test(manifestSha256) || !SHA256.test(configSha256)) {
    throw new Error("Gondolin image lock checksum is invalid.");
  }
  if (!isArchitecture(record.arch)) throw new Error("Gondolin image lock architecture is invalid.");
  return {
    schema: GONDOLIN_IMAGE_LOCK_SCHEMA,
    buildId,
    manifestSha256,
    configSha256,
    arch: record.arch,
    gondolinVersion,
  };
}

export function serializeGondolinImageLock(lock: GondolinImageLock): string {
  return `${JSON.stringify(parseGondolinImageLock(lock), null, 2)}\n`;
}

/** Read architecture from a locally cached image manifest without trusting env text. */
export function resolveGondolinImageArchitecture(image: string): Architecture | undefined {
  if (!BUILD_ID.test(image)) return undefined;
  try {
    const manifest = loadAssetManifest(getImageObjectDirectory(image));
    return manifest && isArchitecture(manifest.config.arch) ? manifest.config.arch : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Resolve the libc ABI for a Gondolin image configuration.
 *
 * Gondolin's OCI metadata does not describe libc, so only the pinned uv OCI
 * rootfs used by this integration is accepted as glibc. Unknown OCI roots
 * fail closed rather than selecting incompatible artifacts.
 */
export function resolveGondolinImageLibc(config: {
  readonly distro?: unknown;
  readonly oci?: unknown;
}): "gnu" | "musl" | undefined {
  if (config.oci !== undefined && config.oci !== null) {
    if (typeof config.oci !== "object" || Array.isArray(config.oci)) return undefined;
    const image = (config.oci as { readonly image?: unknown }).image;
    return typeof image === "string" && /^ghcr\.io\/astral-sh\/uv@sha256:[0-9a-f]{64}$/i.test(image)
      ? "gnu"
      : undefined;
  }
  if (config.distro === "alpine") return "musl";
  if (config.distro === "nixos") return "gnu";
  return undefined;
}

/** Resolve the uv target from the verified image's architecture and rootfs ABI. */
export function resolveGondolinImageUvTarget(image: string): UvPythonTarget | undefined {
  if (!BUILD_ID.test(image)) return undefined;
  try {
    const manifest = loadAssetManifest(getImageObjectDirectory(image));
    if (!manifest || !isArchitecture(manifest.config.arch)) return undefined;
    const libc = resolveGondolinImageLibc(manifest.config);
    return libc ? `${manifest.config.arch}-unknown-linux-${libc}` as UvPythonTarget : undefined;
  } catch {
    return undefined;
  }
}

export async function writeGondolinBuildConfig(workspaceRoot: string, config: BuildConfig): Promise<string> {
  await ensureMetadataDirectory(workspaceRoot);
  const configPath = metadataFilePath(workspaceRoot, "build-config.json", true);
  const temporaryPath = `${configPath}.tmp-${randomUUID()}`;
  await writeFile(temporaryPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  await rename(temporaryPath, configPath);
  return configPath;
}

export async function writeGondolinImageLock(workspaceRoot: string, lock: GondolinImageLock): Promise<string> {
  await ensureMetadataDirectory(workspaceRoot);
  const lockPath = metadataFilePath(workspaceRoot, "image-lock.json", true);
  const temporaryPath = `${lockPath}.tmp-${randomUUID()}`;
  await writeFile(temporaryPath, serializeGondolinImageLock(lock), "utf8");
  await rename(temporaryPath, lockPath);
  return lockPath;
}

export function readGondolinImageLock(workspaceRoot: string): GondolinImageLock | undefined {
  const paths = workspaceProfilePaths(workspaceRoot);
  if (!paths || !existsSync(paths.lockPath)) return undefined;
  return parseGondolinImageLock(JSON.parse(readFileSync(paths.lockPath, "utf8")));
}

export interface GondolinImageBuildDependencies {
  buildAssets: typeof gondolinBuildAssets;
  verifyAssets: typeof verifyAssets;
  importImageFromDirectory: typeof importImageFromDirectory;
  loadAssetManifest: typeof loadAssetManifest;
  getAssetVersion: typeof getAssetVersion;
}

export interface GondolinImageBuildResult {
  readonly buildId: string;
  readonly assetDir: string;
  readonly configPath: string;
  readonly lockPath: string;
  readonly detected: readonly string[];
}

const DEFAULT_BUILD_DEPENDENCIES: GondolinImageBuildDependencies = {
  buildAssets: gondolinBuildAssets,
  verifyAssets,
  importImageFromDirectory,
  loadAssetManifest,
  getAssetVersion,
};

async function runIsolatedGondolinBuild(
  config: BuildConfig,
  outputDir: string,
  buildPath: string,
  workspaceRoot: string,
  signal?: AbortSignal,
): Promise<void> {
  const configDir = await mkdtemp(join(tmpdir(), "gondolin-image-config-"));
  const configPath = join(configDir, "build-config.json");
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  const script = `import { readFileSync } from "node:fs";\nimport { buildAssets } from "@earendil-works/gondolin";\nconst [configPath, outputDir, configDir] = process.argv.slice(1, 4);\nawait buildAssets(JSON.parse(readFileSync(configPath, "utf8")), { outputDir, configDir, verbose: false });`;
  const builderNode = existsSync("/usr/bin/node") ? "/usr/bin/node" : process.execPath;
  const env: NodeJS.ProcessEnv = {
    PATH: buildPath,
    HOME: configDir,
    TMPDIR: configDir,
    LANG: "C",
    LC_ALL: "C",
  };
  if (builderNode === process.execPath) {
    for (const name of ["LD_LIBRARY_PATH", "LIBRARY_PATH"]) {
      const value = process.env[name]?.trim();
      if (value) env[name] = resolveGondolinBuildPath(value, workspaceRoot);
    }
  }
  try {
    await execFileAsync(builderNode, ["--input-type=module", "-e", script, configPath, outputDir, configDir], {
      cwd: PACKAGE_ROOT,
      env,
      maxBuffer: 4 * 1024 * 1024,
      signal,
    });
  } catch (error) {
    const detail = (error as { stderr?: string }).stderr?.trim();
    throw new Error(`Gondolin custom image build failed${detail ? `: ${detail}` : "."}`);
  } finally {
    await rm(configDir, { recursive: true, force: true });
  }
}

const activeImageBuilds = new Set<string>();
const BUILD_LEASE_MAX_AGE_MS = 30 * 60 * 1000;

async function acquireGondolinBuildLease(workspaceRoot: string): Promise<() => Promise<void>> {
  const lockDirectory = join(homedir(), ".cache", "gondolin", "workspace-build-locks");
  await mkdir(lockDirectory, { recursive: true, mode: 0o700 });
  const lockPath = join(lockDirectory, `${createHash("sha256").update(workspaceRoot).digest("hex")}.lock`);
  const token = `${process.pid}:${randomUUID()}`;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      await handle.writeFile(token, "utf8");
      await handle.close();
      return async () => {
        try {
          if ((await readFileAsync(lockPath, "utf8")).trim() === token) await unlink(lockPath);
        } catch {
          // Lease was already reclaimed or removed.
        }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const stats = statSync(lockPath);
        const stale = Date.now() - stats.mtimeMs > BUILD_LEASE_MAX_AGE_MS;
        const lock = (await readFileAsync(lockPath, { encoding: "utf8" })).trim();
        const pid = Number(lock.split(":", 1)[0]);
        let alive = false;
        if (Number.isInteger(pid) && pid > 0) {
          try {
            process.kill(pid, 0);
            alive = true;
          } catch (probeError) {
            alive = (probeError as NodeJS.ErrnoException).code !== "ESRCH";
          }
        }
        if (!stale || alive) throw new Error("Gondolin image build is already in progress for this workspace.");
        await unlink(lockPath);
      } catch (probeError) {
        if (probeError instanceof Error && /already in progress/.test(probeError.message)) throw probeError;
        throw new Error("Gondolin workspace build lease is unavailable.");
      }
    }
  }
  throw new Error("Gondolin image build is already in progress for this workspace.");
}

export async function buildGondolinWorkspace(
  workspaceRoot: string,
  options: {
    plan?: GondolinWorkspacePlan;
    dependencies?: Partial<GondolinImageBuildDependencies>;
    signal?: AbortSignal;
  } = {},
): Promise<GondolinImageBuildResult> {
  const root = canonicalWorkspaceRoot(workspaceRoot);
  if (activeImageBuilds.has(root)) throw new Error("Gondolin image build is already in progress for this workspace.");
  const releaseLease = await acquireGondolinBuildLease(root);
  activeImageBuilds.add(root);
  try {
    return await buildGondolinWorkspaceInternal(root, options);
  } finally {
    activeImageBuilds.delete(root);
    await releaseLease();
  }
}

async function buildGondolinWorkspaceInternal(
  workspaceRoot: string,
  options: {
    plan?: GondolinWorkspacePlan;
    dependencies?: Partial<GondolinImageBuildDependencies>;
    signal?: AbortSignal;
  } = {},
): Promise<GondolinImageBuildResult> {
  if (options.signal?.aborted) throw new Error("Gondolin image build aborted.");
  const plan = options.plan ?? planGondolinWorkspace(workspaceRoot);
  const dependencies = { ...DEFAULT_BUILD_DEPENDENCIES, ...options.dependencies };
  const useIsolatedBuilder = options.dependencies === undefined;
  const buildPath = useIsolatedBuilder ? resolveGondolinBuildPath(process.env.PI_GONDOLIN_BUILD_PATH, workspaceRoot) : undefined;
  if (buildPath) {
    const missing = missingGondolinBuildCommands(buildPath);
    if (missing.length > 0) throw new Error(`Gondolin custom image build requires host commands in trusted PATH: ${missing.join(", ")}.`);
  }
  const outputDir = await mkdtemp(join(tmpdir(), "gondolin-image-build-"));
  try {
    let result: Awaited<ReturnType<typeof gondolinBuildAssets>>;
    if (buildPath) {
      await runIsolatedGondolinBuild(plan.config, outputDir, buildPath, workspaceRoot, options.signal);
      result = {
        outputDir,
        manifestPath: join(outputDir, "manifest.json"),
        manifest: dependencies.loadAssetManifest(outputDir) as Awaited<ReturnType<typeof gondolinBuildAssets>>["manifest"],
      };
    } else {
      result = await dependencies.buildAssets(plan.config, {
        outputDir,
        configDir: workspaceRoot,
        verbose: false,
      });
    }
    if (options.signal?.aborted) throw new Error("Gondolin image build aborted.");
    if (!dependencies.verifyAssets(result.outputDir)) {
      throw new Error("Gondolin custom image failed checksum verification.");
    }
    const imported = dependencies.importImageFromDirectory(result.outputDir);
    const manifest = dependencies.loadAssetManifest(imported.assetDir);
    if (!manifest || manifest.buildId !== imported.buildId || manifest.config.arch !== imported.arch) {
      throw new Error("Gondolin custom image manifest does not match imported assets.");
    }

    const configPath = await writeGondolinBuildConfig(workspaceRoot, plan.config);
    const lock = parseGondolinImageLock({
      schema: GONDOLIN_IMAGE_LOCK_SCHEMA,
      buildId: imported.buildId,
      manifestSha256: sha256File(join(imported.assetDir, "manifest.json")),
      configSha256: sha256File(configPath),
      arch: imported.arch,
      gondolinVersion: dependencies.getAssetVersion(),
    });
    const lockPath = await writeGondolinImageLock(workspaceRoot, lock);
    return { buildId: imported.buildId, assetDir: imported.assetDir, configPath, lockPath, detected: plan.detected };
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Resolve only a locally imported, manifest-verified workspace image. */
export function resolveWorkspaceGondolinImage(workspaceRoot: string): string | undefined {
  const paths = workspaceProfilePaths(workspaceRoot);
  if (!paths) return undefined;
  const hasConfig = existsSync(paths.configPath);
  const hasLock = existsSync(paths.lockPath);
  if (!hasConfig && !hasLock) return undefined;
  if (!hasConfig || !hasLock) throw new Error("Gondolin workspace image profile is incomplete.");
  const lock = parseGondolinImageLock(JSON.parse(readFileSync(paths.lockPath, "utf8")));
  try {
    const configPath = paths.configPath;
    const assetDir = getImageObjectDirectory(lock.buildId);
    const manifestPath = join(assetDir, "manifest.json");
    const manifest = loadAssetManifest(assetDir);
    const workspaceConfig = parseBuildConfig(readFileSync(configPath, "utf8"));
    const manifestConfig = manifest ? parseBuildConfig(JSON.stringify(manifest.config)) : undefined;
    if (lock.gondolinVersion !== getAssetVersion() ||
      !manifest || manifest.buildId !== lock.buildId || manifest.config.arch !== lock.arch ||
      !manifestConfig || serializeBuildConfig(workspaceConfig) !== serializeBuildConfig(manifestConfig) ||
      sha256File(configPath) !== lock.configSha256 || sha256File(manifestPath) !== lock.manifestSha256 ||
      !verifyAssets(assetDir)) {
      throw new Error("Gondolin locked image manifest or checksums do not match.");
    }
  } catch (error) {
    throw new Error(`Gondolin locked image is unavailable or failed verification: ${error instanceof Error ? error.message : String(error)}`);
  }
  return lock.buildId;
}
