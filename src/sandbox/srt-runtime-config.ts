import type { SrtCommandSpec } from "./srt-command-spec.js";
import { getSandboxTempPaths } from "./sandbox-visible-paths.js";

export interface SrtRuntimeConfig {
  network?: {
    allowedDomains: string[];
    deniedDomains: string[];
    strictAllowlist: boolean;
  };
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
  if (spec.allowDocker) {
    throw new Error("SRT helper path does not yet support Docker socket passthrough.");
  }

  if (spec.envDenyPatterns.length > 0) {
    throw new Error("SRT helper path does not yet support env deny pattern parity.");
  }

  const approvedRead = dedupe(spec.unmaskedPaths.map((entry) => entry.path));
  const approvedWrite = dedupe(spec.unmaskedPaths.filter((entry) => entry.writable).map((entry) => entry.path));
  const deniedMaskedPaths = dedupe(spec.maskedShimPlan.maskedDenyPaths);

  const tempPaths = new Set(getSandboxTempPaths());
  const allowRead = dedupe([
    ...spec.runtimeReadAllowPaths.filter((path) => !tempPaths.has(path)),
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
    network: {
      allowedDomains: spec.networkPlan.config.allowedDomains,
      deniedDomains: spec.networkPlan.config.deniedDomains,
      strictAllowlist: spec.networkPlan.unmatchedHostAction === "deny",
    },
    filesystem: {
      allowRead,
      allowWrite,
      denyRead: ["/", ...deniedMaskedReads],
      denyWrite: deniedMaskedPaths.filter((path) => !approvedWrite.includes(path)), 
    },
  };
}
