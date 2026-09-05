import {
  createVirtualDirStats,
  ERRNO,
  formatVirtualEntries,
  normalizeVfsPath,
} from "@earendil-works/gondolin";
import type { Dirent } from "node:fs";
import type {
  VirtualFileHandle,
  VirtualProvider,
  VfsStatfs,
} from "@earendil-works/gondolin";

const ROOT = "/";

interface SourceRoute {
  readonly id: string;
  readonly provider: VirtualProvider;
}

function vfsError(code: number, operation: string, path: string): Error {
  const error = new Error(`${operation} ${path} failed`);
  Object.assign(error, { code, errno: code, syscall: operation, path });
  return error;
}

function withFileTypes(options?: object): boolean {
  return Boolean(options && "withFileTypes" in options && options.withFileTypes === true);
}

function virtualEntries(ids: readonly string[], options?: object): Array<string | Dirent> {
  return formatVirtualEntries([...ids], withFileTypes(options));
}

function emptyStatfs(): VfsStatfs {
  return {
    blocks: 0,
    bfree: 0,
    bavail: 0,
    files: 0,
    ffree: 0,
    bsize: 4096,
    frsize: 4096,
    namelen: 255,
  };
}

/**
 * Fixed-topology, per-session router for parent-approved read-only sources.
 *
 * The provider is mounted once at `/mnt/approved`. Source routes are local to
 * this instance; no host directory is created for the guest mount path.
 */
export class DynamicReadOnlyProvider implements VirtualProvider {
  readonly = true;
  supportsSymlinks = true;
  supportsWatch = false;

  private routes = new Map<string, SourceRoute>();
  private nextId = 1;
  private closed = false;

  /** Add already policy-wrapped read-only source and return its guest path. */
  addSource(provider: VirtualProvider): string {
    this.assertOpen();
    if (!provider || typeof provider.open !== "function" || provider.readonly !== true) {
      throw new Error("Dynamic Gondolin source must be read-only.");
    }

    const id = `m${this.nextId++}`;
    const nextRoutes = new Map(this.routes);
    nextRoutes.set(id, { id, provider });
    this.routes = nextRoutes;
    this.supportsSymlinks = [...nextRoutes.values()].every((route) => route.provider.supportsSymlinks);
    return `/${id}`;
  }

  /** Revoke all routes owned by this VM/session. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const routes = [...this.routes.values()];
    this.routes = new Map();
    await Promise.all(routes.map((route) => {
      const close = (route.provider as VirtualProvider & { close?: () => void | Promise<void> }).close;
      return typeof close === "function" ? close.call(route.provider) : undefined;
    }));
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("Dynamic Gondolin provider is closed.");
  }

  private route(path: string, operation: string): { route: SourceRoute; path: string } {
    this.assertOpen();
    const normalized = normalizeVfsPath(path);
    const separator = normalized.indexOf("/", 1);
    const id = (separator === -1 ? normalized.slice(1) : normalized.slice(1, separator));
    const route = this.routes.get(id);
    if (!route) throw vfsError(ERRNO.ENOENT, operation, path);
    return {
      route,
      path: separator === -1 ? ROOT : normalized.slice(separator),
    };
  }

  private deny(path: string, operation: string): never {
    this.assertOpen();
    throw vfsError(ERRNO.EROFS, operation, path);
  }

  async open(path: string, flags: string, mode?: number): Promise<VirtualFileHandle> {
    if (normalizeVfsPath(path) === ROOT) throw vfsError(ERRNO.EISDIR, "open", path);
    const target = this.route(path, "open");
    return target.route.provider.open(target.path, flags, mode);
  }

  openSync(path: string, flags: string, mode?: number): VirtualFileHandle {
    if (normalizeVfsPath(path) === ROOT) throw vfsError(ERRNO.EISDIR, "open", path);
    const target = this.route(path, "open");
    return target.route.provider.openSync(target.path, flags, mode);
  }

  async stat(path: string, options?: object) {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return createVirtualDirStats();
    }
    const target = this.route(path, "stat");
    return target.path === ROOT
      ? target.route.provider.stat(ROOT, options)
      : target.route.provider.stat(target.path, options);
  }

  statSync(path: string, options?: object) {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return createVirtualDirStats();
    }
    const target = this.route(path, "stat");
    return target.route.provider.statSync(target.path, options);
  }

  async lstat(path: string, options?: object) {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return createVirtualDirStats();
    }
    const target = this.route(path, "lstat");
    return target.route.provider.lstat(target.path, options);
  }

  lstatSync(path: string, options?: object) {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return createVirtualDirStats();
    }
    const target = this.route(path, "lstat");
    return target.route.provider.lstatSync(target.path, options);
  }

  async readdir(path: string, options?: object) {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return virtualEntries([...this.routes.keys()], options);
    }
    const target = this.route(path, "readdir");
    return target.route.provider.readdir(target.path, options);
  }

  readdirSync(path: string, options?: object) {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return virtualEntries([...this.routes.keys()], options);
    }
    const target = this.route(path, "readdir");
    return target.route.provider.readdirSync(target.path, options);
  }

  mkdir(path: string, _options?: object): Promise<void | string> {
    return Promise.reject(this.deny(path, "mkdir"));
  }

  mkdirSync(path: string, _options?: object): void | string {
    return this.deny(path, "mkdir");
  }

  rmdir(path: string): Promise<void> {
    return Promise.reject(this.deny(path, "rmdir"));
  }

  rmdirSync(path: string): void {
    return this.deny(path, "rmdir");
  }

  unlink(path: string): Promise<void> {
    return Promise.reject(this.deny(path, "unlink"));
  }

  unlinkSync(path: string): void {
    return this.deny(path, "unlink");
  }

  rename(oldPath: string, _newPath: string): Promise<void> {
    return Promise.reject(this.deny(oldPath, "rename"));
  }

  renameSync(oldPath: string, _newPath: string): void {
    return this.deny(oldPath, "rename");
  }

  async realpath(path: string, options?: object): Promise<string> {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return ROOT;
    }
    const target = this.route(path, "realpath");
    const resolved = target.route.provider.realpath
      ? await target.route.provider.realpath(target.path, options)
      : target.path;
    return normalizeVfsPath(`/${target.route.id}${resolved}`);
  }

  realpathSync(path: string, options?: object): string {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return ROOT;
    }
    const target = this.route(path, "realpath");
    const resolved = target.route.provider.realpathSync
      ? target.route.provider.realpathSync(target.path, options)
      : target.path;
    return normalizeVfsPath(`/${target.route.id}${resolved}`);
  }

  async readlink(path: string, options?: object): Promise<string> {
    const target = this.route(path, "readlink");
    if (!target.route.provider.readlink) throw vfsError(ERRNO.ENOSYS, "readlink", path);
    return target.route.provider.readlink(target.path, options);
  }

  readlinkSync(path: string, options?: object): string {
    const target = this.route(path, "readlink");
    if (!target.route.provider.readlinkSync) throw vfsError(ERRNO.ENOSYS, "readlink", path);
    return target.route.provider.readlinkSync(target.path, options);
  }

  async access(path: string, mode?: number): Promise<void> {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return;
    }
    const target = this.route(path, "access");
    if (target.route.provider.access) return target.route.provider.access(target.path, mode);
    await target.route.provider.stat(target.path);
  }

  accessSync(path: string, mode?: number): void {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return;
    }
    const target = this.route(path, "access");
    if (target.route.provider.accessSync) return target.route.provider.accessSync(target.path, mode);
    target.route.provider.statSync(target.path);
  }

  async statfs(path: string): Promise<VfsStatfs> {
    if (normalizeVfsPath(path) === ROOT) {
      this.assertOpen();
      return emptyStatfs();
    }
    const target = this.route(path, "statfs");
    return target.route.provider.statfs ? target.route.provider.statfs(target.path) : emptyStatfs();
  }

  watch(path: string): never {
    this.deny(path, "watch");
  }

  watchAsync(path: string): never {
    this.deny(path, "watch");
  }
}
