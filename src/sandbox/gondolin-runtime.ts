import type { Architecture, VM, VirtualFileHandle, VirtualProvider } from "@earendil-works/gondolin";
import { detectPhysicalHostArchitecture } from "./gondolin-architecture.js";
export { detectPhysicalHostArchitecture } from "./gondolin-architecture.js";
import { lstatSync, readdirSync, readlinkSync, statSync, type Stats } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { DynamicReadOnlyProvider } from "./gondolin-dynamic-mount.js";
import { resolveGondolinImageArchitecture } from "./gondolin-image-config.js";
import type { GondolinNetworkRequest } from "./gondolin-policy.js";
import {
  canonicalReadOnlySourceRoot,
  canonicalStaticMountSourceRoot,
  gondolinReadOnlySourceIdentity,
} from "./gondolin-session.js";
import type {
  GondolinPolicyWorkspaceMount,
  GondolinRuntime,
  GondolinRuntimeCreateOptions,
  GondolinRuntimeOperations,
  GondolinRuntimeSecret,
} from "./gondolin-session.js";

const GUEST_WORKSPACE = "/workspace";
const GUEST_APPROVED_MOUNTS = "/mnt/approved";
const MASKED_CONTENT = Buffer.from("(masked)");

export type GondolinEmulationPolicy = "deny" | "qemu";

export interface NativeGondolinRuntimeOptions {
  workspaceRoot: string;
  memory?: string;
  cpus?: number;
  emulation?: GondolinEmulationPolicy;
  startTimeoutMs?: number;
  rootfsSize?: string;
}

export interface GondolinVmmSelection {
  emulated: boolean;
  vmm?: "qemu";
  accel?: "hvf" | "tcg";
  cpu?: "max";
}

export function selectGondolinVmm(
  hostArch: Architecture,
  imageArch: Architecture,
  emulation: GondolinEmulationPolicy = "deny",
  platform: NodeJS.Platform = process.platform,
): GondolinVmmSelection {
  if (hostArch === imageArch) return platform === "darwin"
    ? { emulated: false, vmm: "qemu", accel: "hvf", cpu: "max" }
    : { emulated: false };
  if (emulation !== "qemu") {
    throw new Error(
      `Gondolin image architecture ${imageArch} does not match host ${hostArch}; set gondolinEmulation to "qemu" explicitly`,
    );
  }
  return { emulated: true, vmm: "qemu", accel: "tcg", cpu: "max" };
}

export function validateGondolinImageCompatibility(
  image: string,
  emulation: GondolinEmulationPolicy = "deny",
  hostArch: Architecture = detectPhysicalHostArchitecture(),
  platform: NodeJS.Platform = process.platform,
): GondolinVmmSelection {
  const imageArch = resolveGondolinImageArchitecture(image);
  const buildIdImage = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(image);
  if (buildIdImage && !imageArch) throw new Error("Gondolin image manifest is unavailable or invalid");
  return imageArch ? selectGondolinVmm(hostArch, imageArch, emulation, platform) : { emulated: false };
}

const SAFE_ENV_NAMES = new Set(["LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "TERM", "TZ"]);

function asEnv(env: NodeJS.ProcessEnv | undefined): Record<string, string> | undefined {
  if (!env) return undefined;
  return Object.fromEntries(
    Object.entries(env).filter(
      (entry): entry is [string, string] => SAFE_ENV_NAMES.has(entry[0]) && typeof entry[1] === "string",
    ),
  );
}

function normalizeSecretHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

export function validateGondolinSecretScopes(secrets: readonly GondolinRuntimeSecret[]): void {
  const hosts = new Map<string, boolean>();
  for (const secret of secrets) {
    const scoped = (secret.pathPrefixes?.length ?? 0) > 0;
    const seen = new Set<string>();
    for (const host of secret.hosts) {
      const key = normalizeSecretHost(host);
      if (!seen.add(key)) continue;
      const previous = hosts.get(key);
      if (previous !== undefined && (previous || scoped)) {
        throw new Error(`Gondolin secrets cannot share host with scoped credentials: ${host}`);
      }
      hosts.set(key, scoped);
    }
  }
}

export function networkRequest(
  request: Request,
  workspace: GondolinPolicyWorkspaceMount,
  secrets: readonly GondolinRuntimeSecret[] = [],
): boolean {
  try {
    const url = new URL(request.url);
    const decision = workspace.network.request({
      protocol: url.protocol.slice(0, -1),
      domain: url.hostname,
      method: request.method,
    });
    if (decision.decision !== "allow") return false;
    const scopedHosts = secrets.filter((secret) =>
      secret.pathPrefixes &&
      secret.pathPrefixes.length > 0 &&
      secret.hosts.some((host) => normalizeSecretHost(host) === normalizeSecretHost(url.hostname))
    );
    if (scopedHosts.length === 0) return true;
    const method = request.method.toUpperCase();
    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(url.pathname);
    } catch {
      return false;
    }
    if (decodedPath.includes("\u0000") || decodedPath.split("/").includes("..")) return false;
    return (method === "GET" || method === "HEAD") &&
      scopedHosts.some((secret) => secret.pathPrefixes!.some((prefix) => decodedPath.startsWith(prefix)));
  } catch {
    return false;
  }
}

function networkIpRequest(
  info: { hostname: string; protocol: "http" | "https" },
  workspace: GondolinPolicyWorkspaceMount,
): boolean {
  const decision = workspace.network.request({
    protocol: info.protocol,
    domain: info.hostname,
  });
  return decision.decision === "allow";
}

function maskedValue(options?: { encoding?: BufferEncoding } | BufferEncoding): Buffer | string {
  if (typeof options === "string" || (options && typeof options === "object" && options.encoding)) {
    return MASKED_CONTENT.toString(typeof options === "string" ? options : options.encoding);
  }
  return Buffer.from(MASKED_CONTENT);
}

function writeFlags(flags: string | number): boolean {
  return typeof flags === "number" || /[wa+x]/.test(flags);
}

function maskedStats(isDirectory: boolean, options?: object): Stats {
  const bigint = !!(options && typeof options === "object" && "bigint" in options && options.bigint === true);
  const value = (number: number) => bigint ? BigInt(number) : number;
  const mode = isDirectory ? 0o40555 : 0o100444;
  return {
    dev: value(0),
    mode: value(mode),
    nlink: value(1),
    uid: value(0),
    gid: value(0),
    rdev: value(0),
    blksize: value(4096),
    ino: value(0),
    size: value(isDirectory ? 0 : MASKED_CONTENT.length),
    blocks: value(isDirectory ? 0 : 1),
    atimeMs: value(0),
    mtimeMs: value(0),
    ctimeMs: value(0),
    birthtimeMs: value(0),
    atimeNs: value(0),
    mtimeNs: value(0),
    ctimeNs: value(0),
    birthtimeNs: value(0),
    atime: new Date(0),
    mtime: new Date(0),
    ctime: new Date(0),
    birthtime: new Date(0),
    isFile: () => !isDirectory,
    isDirectory: () => isDirectory,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isSymbolicLink: () => false,
    isFIFO: () => false,
    isSocket: () => false,
  } as unknown as Stats;
}

function fileIdentity(stats: Stats): string {
  return `${String(stats.dev)}:${String(stats.ino)}`;
}

class MaskedFileHandle implements VirtualFileHandle {
  readonly path: string | undefined;
  readonly flags: string | undefined;
  readonly mode: number | undefined;
  private maskedPosition = 0;

  constructor(private readonly inner: VirtualFileHandle) {
    this.path = inner.path;
    this.flags = inner.flags;
    this.mode = inner.mode;
  }

  get position(): number | undefined {
    return this.inner.position;
  }

  get closed(): boolean | undefined {
    return this.inner.closed;
  }

  read(buffer: Buffer, offset: number, length: number, position?: number | null): Promise<{ bytesRead: number; buffer: Buffer }> {
    return Promise.resolve(this.readSync(buffer, offset, length, position)).then((bytesRead) => ({ bytesRead, buffer }));
  }

  readSync(buffer: Buffer, offset: number, length: number, position?: number | null): number {
    const usesHandlePosition = position === undefined || position === null;
    const start = Math.max(0, usesHandlePosition ? this.maskedPosition : position);
    if (start >= MASKED_CONTENT.length) return 0;
    const bytesRead = Math.min(length, MASKED_CONTENT.length - start);
    MASKED_CONTENT.copy(buffer, offset, start, start + bytesRead);
    if (usesHandlePosition) this.maskedPosition = start + bytesRead;
    return bytesRead;
  }

  write(): Promise<{ bytesWritten: number; buffer: Buffer }> {
    return Promise.reject(new Error("Gondolin VFS masked handle is read-only"));
  }

  writeSync(): number {
    throw new Error("Gondolin VFS masked handle is read-only");
  }

  readFile(options?: { encoding?: BufferEncoding } | BufferEncoding): Promise<Buffer | string> {
    return Promise.resolve(maskedValue(options));
  }

  readFileSync(options?: { encoding?: BufferEncoding } | BufferEncoding): Buffer | string {
    return maskedValue(options);
  }

  writeFile(): Promise<void> {
    return Promise.reject(new Error("Gondolin VFS masked handle is read-only"));
  }

  writeFileSync(): void {
    throw new Error("Gondolin VFS masked handle is read-only");
  }

  async stat(options?: object): Promise<Stats> {
    const stats = await this.inner.stat(options);
    return maskedStats(stats.isDirectory(), options);
  }

  statSync(options?: object): Stats {
    return maskedStats(this.inner.statSync(options).isDirectory(), options);
  }

  truncate(): Promise<void> {
    return Promise.reject(new Error("Gondolin VFS masked handle is read-only"));
  }

  truncateSync(): void {
    throw new Error("Gondolin VFS masked handle is read-only");
  }

  close(): Promise<void> {
    return this.inner.close();
  }

  closeSync(): void {
    this.inner.closeSync();
  }
}

class PolicyProvider implements VirtualProvider {
  readonly readonly: boolean;
  readonly supportsSymlinks: boolean;
  readonly supportsWatch = false;

  constructor(
    private readonly root: string,
    private readonly delegate: VirtualProvider,
    private readonly workspace: GondolinPolicyWorkspaceMount,
    private readonly rejectUnsafeSourceFiles = false,
  ) {
    this.readonly = delegate.readonly;
    this.supportsSymlinks = delegate.supportsSymlinks;
  }

  private hostPath(path: string): string {
    if (typeof path !== "string") throw new Error("Gondolin VFS path is invalid");
    return resolve(this.root, `.${path.startsWith("/") ? path : `/${path}`}`);
  }

  private assertSafeSourcePath(path: string): void {
    if (!this.rejectUnsafeSourceFiles) return;
    const candidatePath = this.hostPath(path);
    const relativePath = relative(this.root, candidatePath);
    if (relativePath === ".." || relativePath.startsWith(`..${sep}`)) return;
    let current = this.root;
    for (const component of relativePath.split(sep).filter(Boolean)) {
      current = resolve(current, component);
      let linkStats: Stats;
      try {
        linkStats = lstatSync(current);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || code === "ENOTDIR") return;
        throw new Error("Gondolin VFS could not validate source file type.");
      }
      if (linkStats.isSymbolicLink()) {
        const target = readlinkSync(current);
        if (target.startsWith("/") || target.includes("\u0000")) {
          throw new Error("Gondolin VFS denies absolute or invalid symlink targets.");
        }
      }
      let stats: Stats;
      try {
        stats = statSync(current);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || code === "ENOTDIR") return;
        throw new Error("Gondolin VFS could not validate source file type.");
      }
      if (stats.isBlockDevice() || stats.isCharacterDevice() || stats.isFIFO() || stats.isSocket()) {
        throw new Error("Gondolin VFS denies device, FIFO, and socket sources.");
      }
      if (!stats.isDirectory() && component !== relativePath.split(sep).filter(Boolean).at(-1)) {
        throw new Error("Gondolin VFS source path is not a directory.");
      }
    }
  }

  private sensitiveHardlink(path: string): boolean {
    const isSensitivePath = this.workspace.isSensitivePath;
    if (!isSensitivePath) return false;
    const candidatePath = this.hostPath(path);
    let candidateStats: Stats;
    try {
      candidateStats = statSync(candidatePath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return false;
      throw new Error("Gondolin VFS could not validate sensitive file identities.");
    }
    if (!candidateStats.isFile() || Number(candidateStats.nlink) <= 1) return false;
    if (this.rejectUnsafeSourceFiles) return true;

    const sensitiveIdentities = new Set<string>();
    const visit = (directory: string): void => {
      let entries;
      try {
        entries = readdirSync(directory, { withFileTypes: true });
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || code === "ENOTDIR") return;
        throw new Error("Gondolin VFS could not validate sensitive file identities.");
      }
      for (const entry of entries) {
        const hostPath = resolve(directory, entry.name);
        if (isSensitivePath(hostPath)) {
          try {
            const stats = statSync(hostPath);
            if (stats.isFile()) sensitiveIdentities.add(fileIdentity(stats));
          } catch (error) {
            const code = (error as NodeJS.ErrnoException).code;
            if (code !== "ENOENT" && code !== "ENOTDIR") {
              throw new Error("Gondolin VFS could not validate sensitive file identities.");
            }
          }
        }
        if (entry.isDirectory()) visit(hostPath);
      }
    };
    visit(this.root);
    return sensitiveIdentities.has(fileIdentity(candidateStats));
  }

  private readDecision(path: string) {
    this.assertSafeSourcePath(path);
    const result = this.workspace.vfs.read({ operation: "read", path: this.hostPath(path) });
    if (result.decision === "deny") throw new Error(result.reason);
    if (result.decision === "allow" && this.sensitiveHardlink(path)) {
      return {
        ...result,
        decision: "placeholder" as const,
        reason: "Sensitive VFS hardlink read is replaced with the configured placeholder decision.",
      };
    }
    return result;
  }

  private mutationDecision(path: string, operation: string) {
    const result = this.workspace.vfs.mutate({ operation, path: this.hostPath(path) });
    if (result.decision !== "allow") throw new Error(result.reason);
    return result;
  }

  private sourceIdentity(path: string): string | undefined {
    try {
      return fileIdentity(statSync(this.hostPath(path)));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return undefined;
      throw new Error("Gondolin VFS could not validate opened source identity.");
    }
  }

  private validateOpenedSource(stats: Stats, expectedIdentity: string): void {
    if (fileIdentity(stats) !== expectedIdentity) {
      throw new Error("Gondolin VFS source changed during open.");
    }
    if (
      stats.isBlockDevice() ||
      stats.isCharacterDevice() ||
      stats.isFIFO() ||
      stats.isSocket() ||
      (this.rejectUnsafeSourceFiles && Number(stats.nlink) > 1)
    ) {
      throw new Error("Gondolin VFS denies changed device, FIFO, socket, or hardlink sources.");
    }
  }

  async open(path: string, flags: string, mode?: number): Promise<VirtualFileHandle> {
    const isMutation = writeFlags(flags);
    let expectedIdentity: string | undefined;
    if (isMutation) this.mutationDecision(path, "open");
    else {
      this.readDecision(path);
      expectedIdentity = this.sourceIdentity(path);
    }
    const handle = await this.delegate.open(path, flags, mode);
    if (isMutation) return handle;
    try {
      const result = this.readDecision(path);
      if (result.decision === "deny") throw new Error(result.reason);
      if (result.decision === "allow" && expectedIdentity !== undefined) {
        this.validateOpenedSource(await handle.stat(), expectedIdentity);
      }
      return result.decision === "placeholder" ? new MaskedFileHandle(handle) : handle;
    } catch (error) {
      await handle.close().catch(() => {});
      throw error;
    }
  }

  openSync(path: string, flags: string, mode?: number): VirtualFileHandle {
    const isMutation = writeFlags(flags);
    let expectedIdentity: string | undefined;
    if (isMutation) this.mutationDecision(path, "open");
    else {
      this.readDecision(path);
      expectedIdentity = this.sourceIdentity(path);
    }
    const handle = this.delegate.openSync(path, flags, mode);
    if (isMutation) return handle;
    try {
      const result = this.readDecision(path);
      if (result.decision === "deny") throw new Error(result.reason);
      if (result.decision === "allow" && expectedIdentity !== undefined) {
        this.validateOpenedSource(handle.statSync(), expectedIdentity);
      }
      return result.decision === "placeholder" ? new MaskedFileHandle(handle) : handle;
    } catch (error) {
      try {
        handle.closeSync();
      } catch {
        // Preserve the fail-closed policy result when cleanup races.
      }
      throw error;
    }
  }

  async stat(path: string, options?: object) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return maskedStats(false, options);
    const expectedIdentity = this.sourceIdentity(path);
    const stats = await this.delegate.stat(path, options);
    const result = this.readDecision(path);
    if (result.decision === "allow" && expectedIdentity !== undefined && fileIdentity(stats) !== expectedIdentity) {
      throw new Error("Gondolin VFS source changed during stat.");
    }
    return result.decision === "placeholder" ? maskedStats(stats.isDirectory(), options) : stats;
  }

  statSync(path: string, options?: object) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return maskedStats(false, options);
    const expectedIdentity = this.sourceIdentity(path);
    const stats = this.delegate.statSync(path, options);
    const result = this.readDecision(path);
    if (result.decision === "allow" && expectedIdentity !== undefined && fileIdentity(stats) !== expectedIdentity) {
      throw new Error("Gondolin VFS source changed during stat.");
    }
    return result.decision === "placeholder" ? maskedStats(stats.isDirectory(), options) : stats;
  }

  async lstat(path: string, options?: object) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return maskedStats(false, options);
    const stats = await this.delegate.lstat(path, options);
    const result = this.readDecision(path);
    return result.decision === "placeholder" ? maskedStats(stats.isDirectory(), options) : stats;
  }

  lstatSync(path: string, options?: object) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return maskedStats(false, options);
    const stats = this.delegate.lstatSync(path, options);
    const result = this.readDecision(path);
    return result.decision === "placeholder" ? maskedStats(stats.isDirectory(), options) : stats;
  }

  async readdir(path: string, options?: object) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return [];
    const entries = await this.delegate.readdir(path, options);
    return this.readDecision(path).decision === "placeholder" ? [] : entries;
  }

  readdirSync(path: string, options?: object) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return [];
    const entries = this.delegate.readdirSync(path, options);
    return this.readDecision(path).decision === "placeholder" ? [] : entries;
  }

  mkdir(path: string, options?: object) {
    this.mutationDecision(path, "mkdir");
    return this.delegate.mkdir(path, options);
  }

  mkdirSync(path: string, options?: object) {
    this.mutationDecision(path, "mkdir");
    return this.delegate.mkdirSync(path, options);
  }

  rmdir(path: string) {
    this.mutationDecision(path, "rmdir");
    return this.delegate.rmdir(path);
  }

  rmdirSync(path: string) {
    this.mutationDecision(path, "rmdir");
    return this.delegate.rmdirSync(path);
  }

  unlink(path: string) {
    this.mutationDecision(path, "unlink");
    return this.delegate.unlink(path);
  }

  unlinkSync(path: string) {
    this.mutationDecision(path, "unlink");
    return this.delegate.unlinkSync(path);
  }

  rename(oldPath: string, newPath: string) {
    this.mutationDecision(oldPath, "rename");
    this.mutationDecision(newPath, "rename");
    return this.delegate.rename(oldPath, newPath);
  }

  renameSync(oldPath: string, newPath: string) {
    this.mutationDecision(oldPath, "rename");
    this.mutationDecision(newPath, "rename");
    return this.delegate.renameSync(oldPath, newPath);
  }

  async readFile(path: string, options?: { encoding?: BufferEncoding } | BufferEncoding) {
    const handle = await this.open(path, "r");
    try {
      return await handle.readFile(options);
    } finally {
      await handle.close();
    }
  }

  readFileSync(path: string, options?: { encoding?: BufferEncoding } | BufferEncoding) {
    const handle = this.openSync(path, "r");
    try {
      return handle.readFileSync(options);
    } finally {
      handle.closeSync();
    }
  }

  async access(path: string, mode?: number) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return;
    if (this.delegate.access) await this.delegate.access(path, mode);
    else await this.delegate.stat(path);
    this.readDecision(path);
  }

  accessSync(path: string, mode?: number) {
    const initial = this.readDecision(path);
    if (initial.decision === "placeholder") return;
    if (this.delegate.accessSync) this.delegate.accessSync(path, mode);
    else this.delegate.statSync(path);
    this.readDecision(path);
  }

  async exists(path: string) {
    const result = this.readDecision(path);
    if (result.decision === "placeholder") return false;
    const exists = await this.delegate.exists!(path);
    return this.readDecision(path).decision === "placeholder" ? false : exists;
  }

  existsSync(path: string) {
    const result = this.readDecision(path);
    if (result.decision === "placeholder") return false;
    const exists = this.delegate.existsSync!(path);
    return this.readDecision(path).decision === "placeholder" ? false : exists;
  }

  async realpath(path: string, options?: object) {
    const result = this.readDecision(path);
    if (result.decision === "placeholder") return `${GUEST_WORKSPACE}/(masked)`;
    const resolved = await this.delegate.realpath!(path, options);
    return this.readDecision(path).decision === "placeholder"
      ? `${GUEST_WORKSPACE}/(masked)`
      : resolved;
  }

  realpathSync(path: string, options?: object) {
    const result = this.readDecision(path);
    if (result.decision === "placeholder") return `${GUEST_WORKSPACE}/(masked)`;
    const resolved = this.delegate.realpathSync!(path, options);
    return this.readDecision(path).decision === "placeholder"
      ? `${GUEST_WORKSPACE}/(masked)`
      : resolved;
  }

  async readlink(path: string, options?: object) {
    const result = this.readDecision(path);
    if (result.decision === "placeholder") return "(masked)";
    const target = await this.delegate.readlink!(path, options);
    return this.validateSymlinkTarget(path, target);
  }

  readlinkSync(path: string, options?: object) {
    const result = this.readDecision(path);
    if (result.decision === "placeholder") return "(masked)";
    const target = this.delegate.readlinkSync!(path, options);
    return this.validateSymlinkTarget(path, target);
  }

  private validateSymlinkTarget(path: string, target: unknown): string {
    if (typeof target !== "string" || target.startsWith("/") || target.includes("\u0000")) {
      throw new Error("Gondolin VFS denies absolute or invalid symlink targets.");
    }
    const targetResult = this.workspace.vfs.read({
      operation: "read",
      path: this.hostPath(path),
      resolvedTargetPath: resolve(dirname(this.hostPath(path)), target),
    });
    if (targetResult.decision === "deny") throw new Error(targetResult.reason);
    return targetResult.decision === "placeholder" ? "(masked)" : target;
  }

  watch(): never {
    throw new Error("Gondolin VFS watch is unsupported");
  }

  watchAsync(): never {
    throw new Error("Gondolin VFS watch is unsupported");
  }
}

function createRuntimeOperations(vm: VM, runtimeEnvironment?: Readonly<Record<string, string>>): GondolinRuntimeOperations {
  return {
    async exec(command, cwd, options) {
      const controller = new AbortController();
      const onAbort = () => controller.abort();
      options.signal?.addEventListener("abort", onAbort, { once: true });
      const timer = options.timeout && options.timeout > 0
        ? setTimeout(() => controller.abort(), options.timeout * 1000)
        : undefined;
      try {
        const process = vm.exec(command, {
          cwd,
          env: { HOME: "/root", UV_LINK_MODE: "copy", ...(runtimeEnvironment ?? {}), ...(asEnv(options.env) ?? {}) },
          signal: controller.signal,
          stdout: "pipe",
          stderr: "pipe",
        });
        const output = (async () => {
          for await (const chunk of process.output()) options.onData(chunk.data);
        })();
        const [result] = await Promise.all([process, output]);
        return { exitCode: result.exitCode };
      } finally {
        if (timer) clearTimeout(timer);
        options.signal?.removeEventListener("abort", onAbort);
      }
    },
    fs: {
      access: (path) => vm.fs.access(path),
      readFile: async (path) => Buffer.from(await vm.fs.readFile(path, { encoding: null })),
      writeFile: (path, content) => vm.fs.writeFile(path, content),
      mkdir: (path, options) => vm.fs.mkdir(path, options),
    },
  };
}

export function createNativeGondolinRuntime(options: NativeGondolinRuntimeOptions): GondolinRuntime {
  return {
    async createSession(runtimeOptions: GondolinRuntimeCreateOptions) {
      const { createHttpHooks, RealFSProvider, ReadonlyProvider, VM } = await import("@earendil-works/gondolin");
      validateGondolinSecretScopes(runtimeOptions.secrets ?? []);
      const secrets = Object.fromEntries((runtimeOptions.secrets ?? []).map((secret) => [secret.name, {
        hosts: [...secret.hosts],
        value: secret.value,
      }]));
      const { httpHooks, env: secretEnv } = createHttpHooks({
        allowedHosts: ["*"],
        secrets,
        isRequestAllowed: (request) => networkRequest(request, runtimeOptions.workspace, runtimeOptions.secrets),
        isIpAllowed: (info) => networkIpRequest(info, runtimeOptions.workspace),
      });
      const provider = new PolicyProvider(options.workspaceRoot, new RealFSProvider(options.workspaceRoot), runtimeOptions.workspace);
      const dynamicMount = new DynamicReadOnlyProvider();
      const mounts: Record<string, VirtualProvider> = {
        [GUEST_WORKSPACE]: provider,
        "/mnt/approved": dynamicMount,
      };
      for (const mount of runtimeOptions.mounts ?? []) {
        const guestPath = resolve("/", mount.guestPath);
        if (
          !mount.readOnly ||
          guestPath === GUEST_APPROVED_MOUNTS ||
          guestPath.startsWith(`${GUEST_APPROVED_MOUNTS}/`)
        ) {
          throw new Error("Gondolin host mounts must be read-only and cannot replace the dynamic mount.");
        }
        const hostRoot = canonicalStaticMountSourceRoot(mount.hostRoot);
        const delegate = new RealFSProvider(hostRoot);
        mounts[mount.guestPath] = new PolicyProvider(
          hostRoot,
          mount.readOnly ? new ReadonlyProvider(delegate) : delegate,
          mount.workspace,
          true,
        );
      }
      const vmm = validateGondolinImageCompatibility(runtimeOptions.image, options.emulation);
      const vm = await VM.create({
        sandbox: {
          imagePath: runtimeOptions.image,
          memory: options.memory ?? "2G",
          cpus: options.cpus,
          ...(vmm.vmm ? { vmm: vmm.vmm, accel: vmm.accel, cpu: vmm.cpu } : {}),
        },
        startTimeoutMs: options.startTimeoutMs ?? (vmm.emulated ? 120_000 : 30_000),
        rootfs: { size: options.rootfsSize ?? "16G" },
        vfs: { mounts },
        httpHooks,
        env: {
          HOME: "/root",
          PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
          ...(runtimeOptions.environment ?? {}),
          ...secretEnv,
        },
        dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
        allowWebSockets: false,
      });
      return {
        close: async () => {
          await dynamicMount.close();
          await vm.close();
        },
        addReadOnlySource: (source) => {
          const hostRoot = canonicalReadOnlySourceRoot(source.hostRoot);
          if (gondolinReadOnlySourceIdentity(hostRoot) !== source.identity) {
            throw new Error("Gondolin read-only source identity changed; approval is required again.");
          }
          const delegate = new RealFSProvider(hostRoot);
          const guestPath = dynamicMount.addSource(new PolicyProvider(
            hostRoot,
            new ReadonlyProvider(delegate),
            source.workspace,
            true,
          ));
          return `${GUEST_APPROVED_MOUNTS}${guestPath}`;
        },
        operations: createRuntimeOperations(vm, runtimeOptions.environment),
      };
    },
  };
}
