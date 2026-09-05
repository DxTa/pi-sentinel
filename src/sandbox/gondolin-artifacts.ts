import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, type FileHandle, mkdtemp, open, realpath, rename, rm } from "node:fs/promises";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import type { GondolinRuntimeSecret } from "./gondolin-session.js";

export type UvPythonTarget = "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" | "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl";

export interface LockedUvArtifact {
  readonly kind: "wheel" | "sdist";
  readonly url: string;
  readonly hash: string;
}

export type UvDependencyPreparationMode = "offline" | "brokered-network";

export interface PreparedSandboxMount {
  readonly hostRoot: string;
  readonly guestPath: string;
}

export interface PreparedSandboxResources {
  readonly kind: string;
  readonly mounts: readonly PreparedSandboxMount[];
  readonly environment: Readonly<Record<string, string>>;
  readonly secrets?: readonly GondolinRuntimeSecret[];
  cleanup(): Promise<void>;
}

export type PreparedDependencyArtifacts = PreparedSandboxResources;

export interface TrustedArtifactOrigin {
  readonly hostname: string;
  readonly pathPrefix: string;
}

interface HostCommandResult {
  readonly stdout: string;
  readonly stderr: string;
}

type HostCommandRunner = (command: string, args: readonly string[], signal?: AbortSignal) => Promise<HostCommandResult>;
type ArtifactFetcher = (url: string, init: {
  readonly headers?: Readonly<Record<string, string>>;
  readonly redirect: "error";
  readonly signal?: AbortSignal;
}) => Promise<{
  readonly ok: boolean;
  readonly status: number;
  readonly headers: Pick<Headers, "get">;
  readonly body: ReadableStream<Uint8Array> | null;
}>;

export interface UvDependencyArtifactPreparationOptions {
  readonly workspaceRoot: string;
  readonly target: UvPythonTarget;
  readonly mode?: UvDependencyPreparationMode;
  readonly signal?: AbortSignal;
  readonly tempRoot?: string;
  readonly parseLock?: (lockPath: string, target: UvPythonTarget) => Promise<readonly LockedUvArtifact[]>;
  readonly runHostCommand?: HostCommandRunner;
  readonly fetchArtifact?: ArtifactFetcher;
  readonly trustedArtifactOrigins?: readonly TrustedArtifactOrigin[];
  readonly trustedWorkspaceRoots?: readonly string[];
}

const GOOGLE_ARTIFACT_REGISTRY_SUFFIX = ".pkg.dev";
const MAX_LOCK_BYTES = 8 * 1024 * 1024;
const MAX_ARTIFACT_COUNT = 2048;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024;
const HOST_COMMAND_TIMEOUT_MS = 30_000;
const ARTIFACT_FETCH_TIMEOUT_MS = 120_000;

const PUBLIC_UV_ARTIFACT_ORIGINS: readonly TrustedArtifactOrigin[] = [
  { hostname: "files.pythonhosted.org", pathPrefix: "/packages/" },
];
const UV_PRIVATE_INDEX_NAME = "gondolin-private";
const UV_PRIVATE_INDEX_USERNAME = "oauth2accesstoken";

function defaultRunHostCommand(command: string, args: readonly string[], signal?: AbortSignal): Promise<HostCommandResult> {
  return new Promise((resolvePromise, reject) => {
    execFile(command, [...args], {
      maxBuffer: 1024 * 1024,
      signal,
      timeout: HOST_COMMAND_TIMEOUT_MS,
      env: { ...process.env, CLOUDSDK_CORE_DISABLE_PROMPTS: "1" },
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${command} failed: ${String(stderr).trim() || error.message}`));
        return;
      }
      resolvePromise({ stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

function parseUvArtifactRecord(record: string, kind: LockedUvArtifact["kind"]): LockedUvArtifact | undefined {
  const url = record.match(/\burl\s*=\s*"([^"]+)"/)?.[1];
  const hash = record.match(/\bhash\s*=\s*"([^"]+)"/)?.[1];
  return url && hash ? { kind, url, hash } : undefined;
}

export function parseUvLockArtifacts(lockContent: string, _target: UvPythonTarget): readonly LockedUvArtifact[] {
  const artifacts: LockedUvArtifact[] = [];
  for (const packageBlock of lockContent.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const sdistRecord = packageBlock.match(/^\s*sdist\s*=\s*\{([^{}]*)\}/m)?.[1];
    const wheelSection = packageBlock.match(/^\s*wheels\s*=\s*\[([\s\S]*?)\]/m)?.[1] ?? "";
    const wheelCandidates = [...wheelSection.matchAll(/\{([^{}]*)\}/g)].flatMap((match) => {
      const artifact = parseUvArtifactRecord(match[1] ?? "", "wheel");
      return artifact ? [artifact] : [];
    });
    const sdist = sdistRecord ? parseUvArtifactRecord(sdistRecord, "sdist") : undefined;
    if (sdist) artifacts.push(sdist);
    artifacts.push(...wheelCandidates);
  }
  return artifacts;
}

async function readUvLock(lockPath: string, workspaceRoot: string): Promise<string> {
  let rootPath: string;
  try {
    rootPath = await realpath(workspaceRoot);
  } catch {
    throw new Error("uv workspace root is unavailable.");
  }
  let lockFile: FileHandle;
  try {
    lockFile = await open(lockPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw error;
  }
  try {
    const lockStat = await lockFile.stat();
    const lockPathResolved = resolve(rootPath, relative(rootPath, await realpath(lockPath)));
    const lockRelativePath = relative(rootPath, lockPathResolved);
    if (!lockStat.isFile() || lockStat.nlink !== 1 || lockStat.size > MAX_LOCK_BYTES || lockRelativePath === ".." || lockRelativePath.startsWith("../")) {
      throw new Error("uv.lock must be a regular, single-link file inside the workspace and below the size limit.");
    }
    const chunks: Buffer[] = [];
    let bytesRead = 0;
    while (bytesRead <= MAX_LOCK_BYTES) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_LOCK_BYTES + 1 - bytesRead));
      const result = await lockFile.read(chunk, 0, chunk.length, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
      chunks.push(chunk.subarray(0, result.bytesRead));
      if (bytesRead > MAX_LOCK_BYTES) throw new Error("uv.lock must be a regular, single-link file inside the workspace and below the size limit.");
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    await lockFile.close();
  }
}

function parseUvLockContent(lockContent: string, target: UvPythonTarget): readonly LockedUvArtifact[] {
  return parseUvLockArtifacts(lockContent, target);
}

function isGoogleArtifactRegistryUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:" && new URL(url).hostname.endsWith(GOOGLE_ARTIFACT_REGISTRY_SUFFIX);
  } catch {
    return false;
  }
}

async function isTrustedWorkspace(workspaceRoot: string, trustedRoots: readonly string[]): Promise<boolean> {
  let canonicalWorkspaceRoot: string;
  try {
    canonicalWorkspaceRoot = await realpath(workspaceRoot);
  } catch {
    return false;
  }
  for (const trustedRoot of trustedRoots) {
    try {
      const relativeWorkspaceRoot = relative(await realpath(trustedRoot), canonicalWorkspaceRoot);
      if (relativeWorkspaceRoot === "" || (relativeWorkspaceRoot !== ".." && !relativeWorkspaceRoot.startsWith(`..${sep}`))) return true;
    } catch {
      // A configured root that no longer exists cannot authorize artifact access.
    }
  }
  return false;
}

function artifactFilename(url: string): string {
  const filename = basename(new URL(url).pathname);
  if (!filename || filename === "." || filename === ".." || filename.includes("\u0000")) {
    throw new Error("uv.lock contains an invalid artifact URL.");
  }
  return filename;
}

function normalizedArtifactPathPrefix(pathPrefix: string): string | undefined {
  if (!pathPrefix.startsWith("/")) return undefined;
  return pathPrefix.endsWith("/") ? pathPrefix : `${pathPrefix}/`;
}

function artifactMatchesOrigin(url: string, origin: TrustedArtifactOrigin): boolean {
  try {
    const parsedUrl = new URL(url);
    const pathPrefix = normalizedArtifactPathPrefix(origin.pathPrefix);
    return parsedUrl.hostname === origin.hostname && pathPrefix !== undefined && parsedUrl.pathname.startsWith(pathPrefix);
  } catch {
    return false;
  }
}

function privateRegistryOrigins(
  artifacts: readonly LockedUvArtifact[],
  trustedOrigins: readonly TrustedArtifactOrigin[],
): readonly TrustedArtifactOrigin[] {
  return trustedOrigins.filter((origin) => origin.hostname.endsWith(GOOGLE_ARTIFACT_REGISTRY_SUFFIX) && artifacts.some((artifact) => artifactMatchesOrigin(artifact.url, origin)));
}

function privateIndexPath(pathPrefix: string): string {
  const prefix = normalizedArtifactPathPrefix(pathPrefix);
  if (!prefix) throw new Error("Private uv registry path prefix is invalid.");
  return prefix.endsWith("/simple/") ? prefix : `${prefix}simple/`;
}

function trustedArtifactUrl(url: string, trustedOrigins: readonly TrustedArtifactOrigin[]): URL {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error("uv.lock contains an invalid artifact URL.");
  }
  const trusted = parsedUrl.protocol === "https:"
    && parsedUrl.username === ""
    && parsedUrl.password === ""
    && (parsedUrl.port === "" || parsedUrl.port === "443")
    && isIP(parsedUrl.hostname) === 0
    && trustedOrigins.some((origin) => {
      const pathPrefix = normalizedArtifactPathPrefix(origin.pathPrefix);
      return pathPrefix !== undefined && parsedUrl.hostname === origin.hostname && parsedUrl.pathname.startsWith(pathPrefix);
    });
  if (!trusted) throw new Error(`uv artifact URL is not an approved registry path: ${parsedUrl.hostname}${parsedUrl.pathname}`);
  return parsedUrl;
}

async function fetchLockedArtifact(
  artifact: LockedUvArtifact,
  hostRoot: string,
  token: string | undefined,
  fetchArtifact: ArtifactFetcher,
  signal: AbortSignal | undefined,
  totalBytes: { value: number },
  trustedOrigins: readonly TrustedArtifactOrigin[],
): Promise<void> {
  const parsedUrl = trustedArtifactUrl(artifact.url, trustedOrigins);
  const headers = token ? { authorization: `Bearer ${token}` } : undefined;
  const fetchController = new AbortController();
  const abortFetch = () => fetchController.abort(signal?.reason);
  if (signal?.aborted) fetchController.abort(signal.reason);
  else signal?.addEventListener("abort", abortFetch, { once: true });
  const timeout = setTimeout(() => fetchController.abort(new Error("uv artifact fetch timed out.")), ARTIFACT_FETCH_TIMEOUT_MS);
  try {
    const response = await fetchArtifact(artifact.url, {
      ...(headers ? { headers } : {}),
      redirect: "error",
      signal: fetchController.signal,
    });
    if (!response.ok) throw new Error(`Failed to fetch uv artifact ${parsedUrl.hostname}: HTTP ${response.status}`);
    const declaredBytes = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredBytes) && declaredBytes > MAX_ARTIFACT_BYTES) {
      throw new Error(`uv artifact ${artifactFilename(artifact.url)} exceeds the size limit.`);
    }
    const destination = join(hostRoot, artifactFilename(artifact.url));
    const temporary = `${destination}.tmp-${randomUUID()}`;
    const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    const digest = createHash("sha256");
    let artifactBytes = 0;
    let complete = false;
    try {
      if (!response.body) throw new Error("uv artifact response has no body.");
      const reader = response.body.getReader();
      try {
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          artifactBytes += chunk.value.byteLength;
          totalBytes.value += chunk.value.byteLength;
          if (artifactBytes > MAX_ARTIFACT_BYTES || totalBytes.value > MAX_TOTAL_ARTIFACT_BYTES) {
            throw new Error("uv artifact download exceeds the size limit.");
          }
          digest.update(chunk.value);
          let written = 0;
          while (written < chunk.value.byteLength) {
            const result = await file.write(chunk.value, written, chunk.value.byteLength - written);
            if (result.bytesWritten <= 0) throw new Error("uv artifact write made no progress.");
            written += result.bytesWritten;
          }
        }
      } finally {
        reader.releaseLock();
      }
      const expectedHash = artifact.hash.replace(/^sha256:/, "").toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(expectedHash) || digest.digest("hex") !== expectedHash) {
        throw new Error(`uv artifact hash mismatch for ${artifactFilename(artifact.url)}`);
      }
      complete = true;
    } finally {
      await file.close();
      if (!complete) await rm(temporary, { force: true });
    }
    await rename(temporary, destination);
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", abortFetch);
  }
}

export async function createUvDependencyArtifactPreparation(
  options: UvDependencyArtifactPreparationOptions,
): Promise<PreparedDependencyArtifacts | undefined> {
  const lockPath = join(options.workspaceRoot, "uv.lock");
  const lockContent = await readUvLock(lockPath, options.workspaceRoot);
  if (!lockContent) return undefined;
  if (options.signal?.aborted) throw new Error("uv artifact preparation aborted.");
  const mode = options.mode ?? "offline";
  const runHostCommand = options.runHostCommand ?? defaultRunHostCommand;
  const artifacts = options.parseLock
    ? await options.parseLock(lockPath, options.target)
    : parseUvLockContent(lockContent, options.target);
  const selected = artifacts.filter((artifact, index) => artifacts.findIndex((candidate) => candidate.url === artifact.url) === index);
  if (selected.length > MAX_ARTIFACT_COUNT) throw new Error("uv.lock contains too many artifacts.");
  const trustedOrigins = options.trustedArtifactOrigins ?? PUBLIC_UV_ARTIFACT_ORIGINS;
  const trustedWorkspaceRoots = options.trustedWorkspaceRoots ?? [];
  const filenames = new Set<string>();
  for (const artifact of selected) {
    trustedArtifactUrl(artifact.url, trustedOrigins);
    const filename = artifactFilename(artifact.url);
    if (!filenames.add(filename)) throw new Error(`uv.lock contains duplicate artifact filename: ${filename}`);
  }
  const privateOrigins = privateRegistryOrigins(selected, trustedOrigins);
  const requiresGcloud = privateOrigins.length > 0;
  if (requiresGcloud && !(await isTrustedWorkspace(options.workspaceRoot, trustedWorkspaceRoots))) {
    throw new Error("Private uv artifacts require explicit trust for this workspace.");
  }
  let token: string | undefined;
  if (requiresGcloud) {
    const auth = await runHostCommand("gcloud", ["auth", "print-access-token"], options.signal);
    token = auth.stdout.trim();
    if (!token) throw new Error("gcloud returned no access token for private uv artifacts.");
  }
  const environment: Record<string, string> = mode === "offline"
    ? {
        UV_CACHE_DIR: "/tmp/pi-uv-cache",
        UV_FIND_LINKS: "/mnt/pi-uv-artifacts",
        UV_LINK_MODE: "copy",
        UV_LOCKED: "1",
        UV_NO_INDEX: "1",
        UV_OFFLINE: "1",
        UV_PROJECT_ENVIRONMENT: "/tmp/pi-uv-venv",
      }
    : {
        UV_CACHE_DIR: "/tmp/pi-uv-cache",
        UV_INDEX_STRATEGY: "first-index",
        UV_LINK_MODE: "copy",
        UV_LOCKED: "1",
        UV_PROJECT_ENVIRONMENT: "/tmp/pi-uv-venv",
      };
  const secrets: GondolinRuntimeSecret[] = [];
  if (mode === "brokered-network" && privateOrigins.length > 0) {
    environment.UV_INDEX = privateOrigins.map((origin, index) => {
      const indexName = index === 0 ? UV_PRIVATE_INDEX_NAME : `${UV_PRIVATE_INDEX_NAME}-${index}`;
      const environmentName = indexName.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
      environment[`UV_INDEX_${environmentName}_USERNAME`] = UV_PRIVATE_INDEX_USERNAME;
      const pathPrefix = normalizedArtifactPathPrefix(origin.pathPrefix);
      if (!pathPrefix) throw new Error("Private uv registry path prefix is invalid.");
      secrets.push({
        name: `UV_INDEX_${environmentName}_PASSWORD`,
        value: token!,
        hosts: [origin.hostname],
        pathPrefixes: [pathPrefix],
      });
      return `${indexName}=https://${origin.hostname}${privateIndexPath(origin.pathPrefix)}`;
    }).join(" ");
  }
  if (mode === "brokered-network") {
    return {
      kind: "uv",
      mounts: [],
      environment,
      secrets,
      async cleanup() {},
    };
  }
  const hostRoot = await mkdtemp(join(options.tempRoot ?? tmpdir(), "pi-gondolin-uv-artifacts-"));
  await chmod(hostRoot, 0o700);
  try {
    const fetchArtifact = options.fetchArtifact ?? (globalThis.fetch as unknown as ArtifactFetcher);
    const totalBytes = { value: 0 };
    for (const artifact of selected) {
      if (options.signal?.aborted) throw new Error("uv artifact preparation aborted.");
      await fetchLockedArtifact(artifact, hostRoot, isGoogleArtifactRegistryUrl(artifact.url) ? token : undefined, fetchArtifact, options.signal, totalBytes, trustedOrigins);
    }
  } catch (error) {
    await rm(hostRoot, { recursive: true, force: true });
    throw error;
  }
  let cleanupPromise: Promise<void> | undefined;
  return {
    kind: "uv",
    mounts: [{ hostRoot, guestPath: "/mnt/pi-uv-artifacts" }],
    environment,
    secrets,
    async cleanup() {
      cleanupPromise ??= rm(hostRoot, { recursive: true, force: true }).catch((error) => {
        cleanupPromise = undefined;
        throw error;
      });
      await cleanupPromise;
    },
  };
}
