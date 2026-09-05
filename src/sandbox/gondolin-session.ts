import { createHash } from "node:crypto";
import { lstatSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, relative, resolve, sep } from "node:path";

import {
  decideGondolinNetworkAccess,
  decideGondolinVfsAccess,
  isGondolinSensitivePath,
  DEFAULT_GONDOLIN_HOME_SENSITIVE_PATHS,
  type GondolinNetworkDecisionResult,
  type GondolinNetworkPolicy,
  type GondolinNetworkRequest,
  type GondolinVfsDecisionResult,
  type GondolinVfsPolicy,
  type GondolinVfsRequest,
} from "./gondolin-policy.js";

export interface GondolinSessionMountPolicy {
  guestPath: string;
  readOnly: boolean;
  vfs: GondolinVfsPolicy;
}

export interface GondolinSessionPolicy {
  vfs: GondolinVfsPolicy;
  network: GondolinNetworkPolicy;
  mounts?: readonly GondolinSessionMountPolicy[];
}

export interface GondolinVfsHooks {
  read(request: GondolinVfsRequest, generation?: number): GondolinVfsHookResult;
  mutate(request: GondolinVfsRequest, generation?: number): GondolinVfsDecisionResult;
}

export interface GondolinNetworkHooks {
  request(request: GondolinNetworkRequest, generation?: number): GondolinNetworkDecisionResult;
  tcp(request?: GondolinTcpRequest | null, generation?: number): GondolinNetworkDecisionResult;
}

export interface GondolinPolicyWorkspaceMount {
  readonly kind: "gondolin-policy-vfs";
  readonly isSensitivePath?: (path: string) => boolean;
  readonly vfs: GondolinVfsHooks;
  readonly network: GondolinNetworkHooks;
}

export interface GondolinTcpRequest {
  domain: string;
  port?: number;
}

export interface GondolinVfsHookResult extends GondolinVfsDecisionResult {
  /** Content supplied by the hook when policy selects masking. */
  content?: string;
}

export interface GondolinRuntimeMount {
  guestPath: string;
  hostRoot: string;
  readOnly: boolean;
  workspace: GondolinPolicyWorkspaceMount;
}

export interface GondolinRuntimeReadOnlySource {
  hostRoot: string;
  workspace: GondolinPolicyWorkspaceMount;
  /** Session-bound canonical source identity; runtime rejects changed roots. */
  identity: string;
}

export interface GondolinReadOnlySource {
  hostRoot: string;
  vfs: GondolinVfsPolicy;
}

export interface GondolinReadOnlySourceValidation {
  readonly hostRoot: string;
  readonly identity: string;
  readonly approvalKey: string;
}

export interface GondolinRuntimeSecret {
  readonly name: string;
  readonly value: string;
  readonly hosts: readonly string[];
  /** Optional request path prefixes for secrets scoped to a package broker. */
  readonly pathPrefixes?: readonly string[];
}

export interface GondolinRuntimeCreateOptions {
  image: string;
  readonly secrets?: readonly GondolinRuntimeSecret[];
  /** Opaque policy VFS mount for workspace operations. */
  workspace: GondolinPolicyWorkspaceMount;
  /** Permission-owned host roots for additional policy-wrapped mounts. */
  mounts?: readonly GondolinRuntimeMount[];
  /** Permission-owned defaults for commands running inside this VM. */
  environment?: Readonly<Record<string, string>>;
}

export interface GondolinRuntimeFileSystem {
  readFile(path: string): Promise<Buffer>;
  access(path: string): Promise<void>;
  writeFile(path: string, content: string): Promise<void>;
  mkdir(path: string, options?: { recursive?: boolean }): Promise<void>;
}

export interface GondolinRuntimeOperations {
  exec(
    command: string,
    cwd: string,
    options: {
      onData: (data: Buffer) => void;
      signal?: AbortSignal;
      timeout?: number;
      env?: NodeJS.ProcessEnv;
    },
  ): Promise<{ exitCode: number | null }>;
  fs: GondolinRuntimeFileSystem;
}

export interface GondolinRuntimeSession {
  close(): void | Promise<void>;
  /** Add one parent-approved, policy-wrapped source to this VM's fixed broker. */
  addReadOnlySource?(source: GondolinRuntimeReadOnlySource): string | Promise<string>;
  /** VM-only operation surface. Host filesystem operations are never accepted here. */
  operations?: GondolinRuntimeOperations;
}

function isRuntimeOperations(value: unknown): value is GondolinRuntimeOperations {
  if (!value || typeof value !== "object") return false;
  const operations = value as Partial<GondolinRuntimeOperations>;
  if (typeof operations.exec !== "function" || !operations.fs || typeof operations.fs !== "object") {
    return false;
  }
  const filesystem = operations.fs as Partial<GondolinRuntimeFileSystem>;
  return typeof filesystem.readFile === "function" &&
    typeof filesystem.access === "function" &&
    typeof filesystem.writeFile === "function" &&
    typeof filesystem.mkdir === "function";
}

export interface GondolinRuntime {
  createSession(
    options: GondolinRuntimeCreateOptions,
  ): GondolinRuntimeSession | null | undefined | Promise<GondolinRuntimeSession | null | undefined>;
}

export interface GondolinSessionCreateOptions {
  runtime: GondolinRuntime | null | undefined;
  image: string | null | undefined;
  secrets?: readonly GondolinRuntimeSecret[];
  workspaceRoot: string | null | undefined;
  policy: GondolinSessionPolicy | null | undefined;
  runtimeEnvironment?: Readonly<Record<string, string>>;
}

export class GondolinSessionError extends Error {
  readonly code: "runtime-unavailable" | "image-unavailable" | "workspace-unavailable" | "policy-unavailable" | "session-unavailable" | "closed" | "stale-generation";

  constructor(
    code: GondolinSessionError["code"],
    message: string,
  ) {
    super(message);
    this.name = "GondolinSessionError";
    this.code = code;
  }
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && !value.includes("\u0000");
}

function isWorkspaceDirectory(workspaceRoot: string): boolean {
  try {
    return statSync(workspaceRoot).isDirectory();
  } catch {
    return false;
  }
}

function canonicalDirectory(path: string): string | null {
  try {
    const canonical = realpathSync.native(resolve(path));
    return isWorkspaceDirectory(canonical) ? canonical : null;
  } catch {
    return null;
  }
}

function sameWorkspaceRoot(first: string, second: string): boolean {
  try {
    return realpathSync.native(resolve(first)) === realpathSync.native(resolve(second));
  } catch {
    return false;
  }
}

const FORBIDDEN_PSEUDO_ROOTS = ["/proc", "/sys", "/dev", "/run", "/var/run"];
const FORBIDDEN_BROAD_ROOTS = ["/etc", "/tmp", "/var"];
const FORBIDDEN_HOST_HOME_ROOTS = ["/root"];
const FORBIDDEN_SOURCE_COMPONENT = /^(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.pi|\.cache|\.config|\.local|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.env(?:\..*)?|credentials?|tokens?|secrets?|passwords?|passwd|auth|keys?|certs?|certificates?|ssl|pki|ca-certificates)$/i;
const SENSITIVE_SOURCE_COMPONENT = /(?:^|[-_.])(?:credential|credentials|token|tokens|secret|secrets|password|passwords|passwd|auth|key|keys|cert|certs|certificate|certificates)(?:$|[-_.])/i;

function isWithinPath(candidate: string, root: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`));
}

function isSensitiveSourceComponent(component: string): boolean {
  return FORBIDDEN_SOURCE_COMPONENT.test(component) || SENSITIVE_SOURCE_COMPONENT.test(component);
}

function isForbiddenSourceRoot(root: string): boolean {
  if (root === resolve("/")) return true;
  if (FORBIDDEN_BROAD_ROOTS.some((prefix) => root === resolve(prefix))) return true;
  if (FORBIDDEN_HOST_HOME_ROOTS.some((prefix) => isWithinPath(root, resolve(prefix)))) return true;
  if (FORBIDDEN_PSEUDO_ROOTS.some((prefix) => isWithinPath(root, resolve(prefix)))) return true;
  try {
    const home = realpathSync.native(resolve(homedir()));
    if (isWithinPath(home, root)) return true;
    const components = relative(resolve("/"), root).split(sep).filter(Boolean);
    if (components.some(isSensitiveSourceComponent)) return true;
    if (isWithinPath(root, home)) {
      return isGondolinSensitivePath(
        { workspaceRoot: home, sensitivePaths: DEFAULT_GONDOLIN_HOME_SENSITIVE_PATHS },
        resolve(root, ".gondolin-source-probe"),
      );
    }
    return false;
  } catch {
    return true;
  }
}

function assertPathChainNotForbidden(path: string): void {
  let current = resolve(path);
  for (let depth = 0; depth < 40; depth += 1) {
    if (isForbiddenSourceRoot(current)) throw new Error("Gondolin read-only source must be a safe directory.");
    let stats: ReturnType<typeof lstatSync>;
    try {
      stats = lstatSync(current);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return;
      throw error;
    }
    if (!stats.isSymbolicLink()) return;
    const target = readlinkSync(current);
    if (target.includes("\u0000")) throw new Error("Gondolin read-only source must be a safe directory.");
    current = resolve(dirname(current), target);
  }
  throw new Error("Gondolin read-only source symlink chain is too deep.");
}

function assertSourcePathNotForbidden(path: string): void {
  const lexicalRoot = resolve(path);
  assertPathChainNotForbidden(lexicalRoot);
  const components = relative(resolve("/"), lexicalRoot).split(sep).filter(Boolean);
  let current = resolve("/");
  for (const component of components) {
    current = resolve(current, component);
    try {
      if (lstatSync(current).isSymbolicLink()) {
        assertPathChainNotForbidden(resolve(dirname(current), readlinkSync(current)));
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
    }
  }
}

export function canonicalReadOnlySourceRoot(path: string): string {
  assertSourcePathNotForbidden(path);
  const canonical = realpathSync.native(resolve(path));
  if (!isWorkspaceDirectory(canonical) || /[\u0001-\u001f\u007f]/.test(canonical) || isForbiddenSourceRoot(canonical)) {
    throw new Error("Gondolin read-only source must be a safe directory.");
  }
  return canonical;
}

export function canonicalStaticMountSourceRoot(path: string): string {
  return canonicalReadOnlySourceRoot(path);
}

function isSafeReadOnlySourceRoot(path: string): boolean {
  try {
    canonicalStaticMountSourceRoot(path);
    return true;
  } catch {
    return false;
  }
}

export function gondolinReadOnlySourceIdentity(hostRoot: string): string {
  const stats = statSync(hostRoot);
  return createHash("sha256")
    .update(`${hostRoot}\u0000${String(stats.dev)}:${String(stats.ino)}`)
    .digest("hex");
}

function sourceApprovalKey(identity: string, policy: GondolinVfsPolicy): string {
  return createHash("sha256")
    .update(JSON.stringify({
      identity,
      sensitivePaths: policy.sensitivePaths ?? null,
      sensitiveReadDecision: policy.sensitiveReadDecision ?? null,
      protectedPaths: policy.protectedPaths ?? null,
    }))
    .digest("hex");
}

function hasValidPolicy(
  policy: GondolinSessionPolicy | null | undefined,
  workspaceRoot: string,
): policy is GondolinSessionPolicy {
  if (!policy || typeof policy !== "object") return false;
  if (
    !policy.vfs ||
    typeof policy.vfs !== "object" ||
    !sameWorkspaceRoot(policy.vfs.workspaceRoot, workspaceRoot)
  ) {
    return false;
  }
  if (!policy.network || typeof policy.network !== "object" || !Array.isArray(policy.network.allowedDomains)) {
    return false;
  }
  if (policy.mounts === undefined) return true;
  if (!Array.isArray(policy.mounts)) return false;
  const guestPaths = new Set(["/workspace"]);
  return policy.mounts.every((mount) => {
    if (!mount || typeof mount !== "object" || typeof mount.guestPath !== "string" ||
      !mount.guestPath.startsWith("/") || typeof mount.readOnly !== "boolean" ||
      !mount.vfs || typeof mount.vfs !== "object" || !isWorkspaceDirectory(mount.vfs.workspaceRoot)) {
      return false;
    }
    const guestPath = resolve("/", mount.guestPath);
    if (
      !mount.readOnly ||
      !isSafeReadOnlySourceRoot(mount.vfs.workspaceRoot) ||
      guestPath === "/mnt/approved" ||
      guestPath.startsWith("/mnt/approved/") ||
      guestPath === "/workspace" ||
      guestPath.startsWith("/workspace/") ||
      guestPaths.has(guestPath) ||
      guestPath !== mount.guestPath
    ) {
      return false;
    }
    guestPaths.add(guestPath);
    return true;
  });
}

interface GondolinHookState {
  active: boolean;
}

export class GondolinSession {
  readonly generation: number;
  readonly workspaceRoot: string;
  readonly image: string;
  readonly vfs: GondolinVfsHooks;
  readonly network: GondolinNetworkHooks;
  readonly operations: GondolinRuntimeOperations | null;

  private closePromise: Promise<void> | null = null;

  constructor(
    private readonly runtimeSession: GondolinRuntimeSession,
    workspaceRoot: string,
    image: string,
    generation: number,
    hooks: GondolinPolicyWorkspaceMount,
    private readonly hookState: GondolinHookState,
    private readonly generationState: GondolinGenerationState,
    private readonly networkPolicy: GondolinNetworkPolicy,
  ) {
    this.workspaceRoot = workspaceRoot;
    this.image = image;
    this.generation = generation;
    this.vfs = hooks.vfs;
    this.network = hooks.network;
    this.operations = isRuntimeOperations(runtimeSession.operations)
      ? runtimeSession.operations
      : null;
  }

  get closed(): boolean {
    return !this.hookState.active;
  }

  validateReadOnlySource(source: GondolinReadOnlySource): GondolinReadOnlySourceValidation {
    if (this.generation !== this.generationState.current) {
      throw new GondolinSessionError("stale-generation", "Gondolin session generation is stale.");
    }
    if (!this.hookState.active) {
      throw new GondolinSessionError("closed", "Gondolin session is closed.");
    }
    if (typeof this.runtimeSession.addReadOnlySource !== "function") {
      throw new GondolinSessionError(
        "session-unavailable",
        "Gondolin runtime does not support dynamic read-only sources.",
      );
    }
    if (
      !source ||
      typeof source !== "object" ||
      !isNonEmptyString(source.hostRoot) ||
      /[\u0001-\u001f\u007f]/.test(source.hostRoot) ||
      !source.vfs ||
      typeof source.vfs !== "object"
    ) {
      throw new GondolinSessionError("policy-unavailable", "Gondolin read-only source is invalid.");
    }
    const sourcePolicy = source.vfs;
    if (
      (sourcePolicy.sensitivePaths !== undefined &&
        (!Array.isArray(sourcePolicy.sensitivePaths) || sourcePolicy.sensitivePaths.some((path) => typeof path !== "string"))) ||
      (sourcePolicy.protectedPaths !== undefined &&
        (!Array.isArray(sourcePolicy.protectedPaths) || sourcePolicy.protectedPaths.some((path) => typeof path !== "string"))) ||
      (sourcePolicy.sensitiveReadDecision !== undefined &&
        sourcePolicy.sensitiveReadDecision !== "placeholder" &&
        sourcePolicy.sensitiveReadDecision !== "deny")
    ) {
      throw new GondolinSessionError("policy-unavailable", "Gondolin read-only source policy is invalid.");
    }
    let hostRoot: string;
    try {
      hostRoot = canonicalReadOnlySourceRoot(source.hostRoot);
    } catch {
      throw new GondolinSessionError(
        "policy-unavailable",
        "Gondolin read-only source must be an existing canonical directory.",
      );
    }
    if (!sameWorkspaceRoot(source.vfs.workspaceRoot, hostRoot)) {
      throw new GondolinSessionError(
        "policy-unavailable",
        "Gondolin read-only source must be an existing canonical directory.",
      );
    }
    const identity = gondolinReadOnlySourceIdentity(hostRoot);
    return {
      hostRoot,
      identity,
      approvalKey: sourceApprovalKey(identity, sourcePolicy),
    };
  }

  async addReadOnlySource(source: GondolinReadOnlySource, expectedApprovalKey?: string): Promise<string> {
    const validation = this.validateReadOnlySource(source);
    if (expectedApprovalKey !== undefined && expectedApprovalKey !== validation.approvalKey) {
      throw new GondolinSessionError("policy-unavailable", "Read-only source identity changed; approval is required again.");
    }
    const { hostRoot, identity } = validation;
    const addReadOnlySource = this.runtimeSession.addReadOnlySource;
    if (typeof addReadOnlySource !== "function") {
      throw new GondolinSessionError(
        "session-unavailable",
        "Gondolin runtime does not support dynamic read-only sources.",
      );
    }
    const workspace = createPolicyWorkspaceMount(
      createPolicyHooks(source.vfs, this.networkPolicy, this.generation, this.generationState, this.hookState),
    );
    const guestPath = await addReadOnlySource({ hostRoot, workspace, identity });
    if (!isNonEmptyString(guestPath)) {
      throw new GondolinSessionError("session-unavailable", "Gondolin runtime returned an invalid source path.");
    }
    return guestPath;
  }

  async close(): Promise<void> {
    if (this.closePromise !== null) return this.closePromise;
    this.hookState.active = false;
    this.closePromise = Promise.resolve()
      .then(() => this.runtimeSession.close())
      .then(() => undefined);
    return this.closePromise;
  }
}

export interface GondolinGenerationState {
  next: number;
  current: number;
}

const DEFAULT_GENERATION_STATE: GondolinGenerationState = { next: 0, current: 0 };

export async function createGondolinSession(
  options: GondolinSessionCreateOptions,
  generationState: GondolinGenerationState = DEFAULT_GENERATION_STATE,
): Promise<GondolinSession> {
  if (!options?.runtime || typeof options.runtime.createSession !== "function") {
    throw new GondolinSessionError("runtime-unavailable", "Gondolin runtime is unavailable.");
  }
  if (!isNonEmptyString(options.image)) {
    throw new GondolinSessionError("image-unavailable", "Gondolin image is unavailable.");
  }
  if (!isNonEmptyString(options.workspaceRoot) || !isWorkspaceDirectory(options.workspaceRoot)) {
    throw new GondolinSessionError("workspace-unavailable", "Gondolin workspace is unavailable.");
  }
  const policy = options.policy;
  if (!hasValidPolicy(policy, options.workspaceRoot)) {
    throw new GondolinSessionError("policy-unavailable", "Gondolin policy is unavailable.");
  }

  const generation = ++generationState.next;
  generationState.current = generation;
  const hookState: GondolinHookState = { active: true };
  const hooks = createPolicyHooks(policy.vfs, policy.network, generation, generationState, hookState);
  const workspace = createPolicyWorkspaceMount(hooks);
  const mounts = policy.mounts?.map((mount) => ({
    guestPath: mount.guestPath,
    hostRoot: canonicalStaticMountSourceRoot(mount.vfs.workspaceRoot),
    readOnly: mount.readOnly,
    workspace: createPolicyWorkspaceMount(
      createPolicyHooks(mount.vfs, policy.network, generation, generationState, hookState),
    ),
  }));
  const runtimeSession = await options.runtime.createSession({
    image: options.image,
    secrets: options.secrets,
    workspace,
    ...(mounts && mounts.length > 0 ? { mounts } : {}),
    ...(options.runtimeEnvironment ? { environment: options.runtimeEnvironment } : {}),
  });
  if (!runtimeSession || typeof runtimeSession.close !== "function") {
    throw new GondolinSessionError("session-unavailable", "Gondolin runtime did not create a session.");
  }
  return new GondolinSession(
    runtimeSession,
    options.workspaceRoot,
    options.image,
    generation,
    hooks,
    hookState,
    generationState,
    policy.network,
  );
}

/**
 * Builds policy hooks before calling the runtime. The runtime never receives a
 * raw workspace adapter or a host fallback operation.
 */
function createPolicyHooks(
  vfsPolicy: GondolinVfsPolicy,
  networkPolicy: GondolinNetworkPolicy,
  generation: number,
  generationState: GondolinGenerationState,
  hookState: GondolinHookState,
): GondolinPolicyWorkspaceMount {
  function assertSessionUsable(generationOverride?: number): void {
    const isStale = generation !== generationState.current ||
      (generationOverride !== undefined && generationOverride !== generation);
    if (isStale) {
      throw new GondolinSessionError("stale-generation", "Gondolin session generation is stale.");
    }
    if (!hookState.active) {
      throw new GondolinSessionError("closed", "Gondolin session is closed.");
    }
  }

  function decideVfs(
    request: GondolinVfsRequest,
    generationOverride?: number,
  ): GondolinVfsDecisionResult {
    assertSessionUsable(generationOverride);
    return decideGondolinVfsAccess(vfsPolicy, request);
  }

  function read(
    request: GondolinVfsRequest,
    generationOverride?: number,
  ): GondolinVfsHookResult {
    const result = decideVfs(request, generationOverride);
    if (result.decision !== "placeholder") return result;
    return { ...result, content: "(masked)" };
  }

  function decideNetwork(
    request: GondolinNetworkRequest,
    generationOverride?: number,
  ): GondolinNetworkDecisionResult {
    assertSessionUsable(generationOverride);
    return decideGondolinNetworkAccess(networkPolicy, request);
  }

  function tcp(
    request?: GondolinTcpRequest | null,
    generationOverride?: number,
  ): GondolinNetworkDecisionResult {
    return decideNetwork(
      { protocol: "tcp", domain: request?.domain ?? "" },
      generationOverride,
    );
  }

  return createPolicyWorkspaceMount({
    isSensitivePath: (path) => isGondolinSensitivePath(vfsPolicy, path),
    vfs: { read, mutate: decideVfs },
    network: { request: decideNetwork, tcp },
  });
}

function createPolicyWorkspaceMount(hooks: {
  isSensitivePath?: (path: string) => boolean;
  vfs: GondolinVfsHooks;
  network: GondolinNetworkHooks;
}): GondolinPolicyWorkspaceMount {
  return { kind: "gondolin-policy-vfs", ...hooks };
}
