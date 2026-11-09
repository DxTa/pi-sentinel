import type { SrtCommandSpec } from "./srt-command-spec.js";
import { DEFAULT_MASKED_PATTERNS, isPathMasked } from "./masked-file-gate.js";
import { isSensitiveEnvPath } from "../path-utils.js";
import { canonicalPath } from "./sandbox-visible-paths.js";
import { isDockerDaemonCommand } from "./bypass-command.js";
import { resolveDockerSocketPaths } from "./docker-socket.js";
import { getSandboxTempPaths } from "./sandbox-visible-paths.js";

export interface SrtRuntimeConfig {
  network?: {
    allowedDomains: string[];
    deniedDomains: string[];
    strictAllowlist: boolean;
    allowUnixSockets?: string[];
    allowAllUnixSockets?: boolean;
  };
  dockerHost?: string;
  filesystem: {
    allowRead: string[];
    allowWrite: string[];
    denyRead: string[];
    denyWrite: string[];
  };
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function isCloudWorkspace(path: string, spec: SrtCommandSpec): boolean {
  const home = spec.homeReadOnly?.path;
  return !!home && (path === spec.cwd || path === spec.repoRoot)
    && ["Library/CloudStorage", "Library/Mobile Documents"].some((root) => path.startsWith(`${home}/${root}/`));
}

function isHomeProtectedPath(path: string, spec: SrtCommandSpec): boolean {
  const access = spec.homeReadOnly;
  if (!access) return false;
  const canonical = canonicalPath(path);
  return access.protectedPaths.some((root) =>
    (canonical === root || canonical.startsWith(`${root}/`)) && !(isCloudWorkspace(canonical, spec) && root === `${access.path}/Library`),
  ) || (!isSensitiveEnvPath(canonical) && isPathMasked(canonical, [...DEFAULT_MASKED_PATTERNS, ...spec.maskedPaths]));
}

export function buildSrtRuntimeConfig(spec: SrtCommandSpec): SrtRuntimeConfig {
  const dockerRequested = spec.allowDocker && isDockerDaemonCommand(spec.command);
  // A missing socket is not a block: the command runs and the CLI reports the connection error itself. The mode policy already gated it.
  const dockerSocketPaths = dockerRequested ? resolveDockerSocketPaths() : [];

  if (spec.envDenyPatterns.length > 0) {
    throw new Error("SRT helper path does not yet support env deny pattern parity.");
  }

  // Unix sockets (docker, ssh-agent, gpg-agent, databases) are reachable from every sandboxed command.
  const allowAllUnixSockets = process.platform === "linux" || process.platform === "darwin";

  const access = spec.homeReadOnly;
  const cloudWorkspace = isCloudWorkspace(spec.cwd, spec) || isCloudWorkspace(spec.repoRoot, spec);
  const isProtected = (path: string) => isHomeProtectedPath(path, spec);
  const approvedRead = dedupe(spec.unmaskedPaths.map((entry) => entry.path).filter((path) => !isProtected(path)));
  const approvedWrite = dedupe(spec.unmaskedPaths.filter((entry) => entry.writable).map((entry) => entry.path).filter((path) => !isProtected(path)));
  const deniedMaskedPaths = dedupe([
    ...spec.maskedShimPlan.maskedDenyPaths,
    ...spec.unmaskedPaths.filter((entry) => isProtected(entry.path)).map((entry) => entry.path),
  ]);
  const deniedWritePaths = dedupe([
    ...deniedMaskedPaths,
    ...spec.unmaskedPaths.filter((entry) => !entry.writable).map((entry) => entry.path),
  ]);

  const tempPaths = new Set(getSandboxTempPaths());
  const allowRead = dedupe([
    ...spec.runtimeReadAllowPaths.filter((path) => !tempPaths.has(path) && !isProtected(path)),
    ...(access ? [access.path] : []),
    ...dockerSocketPaths,
    ...approvedRead,
  ]);
  const deniedMaskedReads = deniedMaskedPaths
    .filter((path) => !approvedRead.includes(path) && !approvedWrite.includes(path));
  const allowWrite = dedupe([
    spec.repoRoot,
    spec.cwd,
    ...spec.rwBinds,
    ...approvedWrite,
  ].filter((path) => !isProtected(path)));

  return {
    ...(dockerSocketPaths.length > 0 ? { dockerHost: `unix://${dockerSocketPaths[0]}` } : {}),
    network: {
      allowedDomains: spec.networkPlan.config.allowedDomains,
      deniedDomains: spec.networkPlan.config.deniedDomains,
      strictAllowlist: spec.networkPlan.unmatchedHostAction === "deny",
      ...(allowAllUnixSockets ? { allowAllUnixSockets: true } : {}),
      ...(dockerSocketPaths.length > 0 ? { allowUnixSockets: dockerSocketPaths } : {}),
    },
    filesystem: {
      allowRead,
      allowWrite,
      denyRead: dedupe(["/", ...deniedMaskedReads, ...(access?.denyPaths ?? [])]),
      denyWrite: [
        ...(access?.denyPaths ?? []).filter((path) => !cloudWorkspace || path !== `${access?.path}/Librar[y]`),
        ...deniedWritePaths.filter((path) => !approvedWrite.includes(path)),
        // An approved target may not exist yet; deny its children so it cannot grow into a writable tree.
        ...approvedWrite.map((path) => `${path}/*`),
      ],
    },
  };
}
