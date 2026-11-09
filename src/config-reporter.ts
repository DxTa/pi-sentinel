import type { ResolvedPolicyPaths } from "./permission-manager";

export interface ResolvedConfigLogEntry {
  bundledConfigPath: string;
  bundledConfigExists: boolean;
  globalConfigPath: string;
  globalConfigExists: boolean;
  projectConfigPath: string | null;
  projectConfigExists: boolean;
  agentsDir: string;
  agentsDirExists: boolean;
  projectAgentsDir: string | null;
  projectAgentsDirExists: boolean;
}

export interface BuildResolvedConfigLogEntryOptions {
  policyPaths: ResolvedPolicyPaths;
}

export function buildResolvedConfigLogEntry(
  options: BuildResolvedConfigLogEntryOptions,
): ResolvedConfigLogEntry {
  return { ...options.policyPaths };
}
