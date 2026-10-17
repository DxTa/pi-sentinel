import type { BashOperations } from "@earendil-works/pi-coding-agent";

import type { DomainGateConfig } from "#src/network/config.js";

import type { UnmaskedPath, ResolvedSandboxProfile, SandboxConfig } from "./types.js";

export interface SandboxWrapInput {
  command: string;
  /** Keep resource-protected commands in SRT even when they match host bypass rules. */
  forceSrt?: boolean;
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
  /** Keep resource-protected commands in SRT even when they match host bypass rules. */
  forceSrt?: boolean;
  sandboxConfig: SandboxConfig;
  cwd: string;
  repoRoot?: string;
  unmaskedPaths?: UnmaskedPath[];
  preResolvedProfile?: ResolvedSandboxProfile;
  secretEnv?: Record<string, string>;
  unifiedConfig?: { network?: DomainGateConfig };
  approvedDomains?: string[];
  outputMasking?: {
    dotenvPaths?: readonly string[];
    redactOutput?: boolean;
  };
}

export type SandboxWrapResult =
  | {
      command: string;
      cleanup?: () => void;
      helperPayloadBytes?: number;
      rawCommandBytes?: number;
    }
  | { block: true; reason: string }
  | undefined;

export interface SandboxBackend {
  kind: string;
  wrapCommand(input: SandboxWrapInput): SandboxWrapResult | Promise<SandboxWrapResult>;
  createBashOperations(input: SandboxOperationsInput): BashOperations;
}
