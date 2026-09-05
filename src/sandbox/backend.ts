import type { BashOperations } from "@earendil-works/pi-coding-agent";

import type { DomainGateConfig } from "#src/network/config.js";

import type { UnmaskedPath } from "./bwrap-command.js";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";

export interface SandboxWrapInput {
  command: string;
  sandboxConfig: SandboxConfig;
  cwd: string;
  repoRoot?: string;
  unmaskedPaths?: UnmaskedPath[];
  preResolvedProfile?: ResolvedSandboxProfile;
  secretEnv?: Record<string, string>;
  unifiedConfig?: { network?: DomainGateConfig };
  approvedDomains?: string[];
}

export interface SandboxOperationsInput {
  sandboxConfig: SandboxConfig;
  cwd: string;
  repoRoot?: string;
  unmaskedPaths?: UnmaskedPath[];
  preResolvedProfile?: ResolvedSandboxProfile;
  secretEnv?: Record<string, string>;
  unifiedConfig?: { network?: DomainGateConfig };
  approvedDomains?: string[];
}

export type SandboxWrapResult =
  | { command: string }
  | { block: true; reason: string }
  | undefined;

export interface SandboxBackend {
  kind: string;
  wrapCommand(input: SandboxWrapInput): SandboxWrapResult | Promise<SandboxWrapResult>;
  createBashOperations(input: SandboxOperationsInput): BashOperations;
}
