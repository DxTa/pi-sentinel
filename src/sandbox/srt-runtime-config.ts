import type { SrtCommandSpec } from "./srt-command-spec.js";
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

export function buildSrtRuntimeConfig(spec: SrtCommandSpec): SrtRuntimeConfig {
  const dockerRequested = spec.allowDocker && isDockerDaemonCommand(spec.command);
  const dockerSocketPaths = dockerRequested ? resolveDockerSocketPaths() : [];
  if (dockerRequested && dockerSocketPaths.length === 0) {
    throw new Error("Docker socket unavailable; command blocked.");
  }

  if (spec.envDenyPatterns.length > 0) {
    throw new Error("SRT helper path does not yet support env deny pattern parity.");
  }

  // Linux SRT cannot scope Unix-socket access by path; Docker needs the broad allowance there.
  const allowAllUnixSockets = process.platform === "linux"
    || (!dockerRequested && process.platform === "darwin");

  const approvedRead = dedupe(spec.unmaskedPaths.map((entry) => entry.path));
  const approvedWrite = dedupe(spec.unmaskedPaths.filter((entry) => entry.writable).map((entry) => entry.path));
  const deniedMaskedPaths = dedupe(spec.maskedShimPlan.maskedDenyPaths);
  const deniedWritePaths = dedupe([
    ...deniedMaskedPaths,
    ...spec.unmaskedPaths.filter((entry) => !entry.writable).map((entry) => entry.path),
  ]);

  const tempPaths = new Set(getSandboxTempPaths());
  const allowRead = dedupe([
    ...spec.runtimeReadAllowPaths.filter((path) => !tempPaths.has(path)),
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
  ]);

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
      denyRead: ["/", ...deniedMaskedReads],
      denyWrite: [
        ...deniedWritePaths.filter((path) => !approvedWrite.includes(path)),
        // An approved target may not exist yet; deny its children so it cannot grow into a writable tree.
        ...approvedWrite.map((path) => `${path}/*`),
      ],
    },
  };
}
