import { existsSync } from "node:fs";
import type { DomainGateConfig } from "#src/network/config.js";

import { commandContainsUvExecutable } from "../handlers/gates/bash-path-extractor.js";
import { resolveSandboxBindPaths, resolveSandboxBindPathsWithinScanBudget } from "./settings.js";
import {
  buildSandboxRuntimeReadAllowPaths,
  buildSandboxVisiblePaths,
  buildSandboxVisiblePathsWithinScanBudget,
  canonicalPath,
  canonicalPathWithinScanBudget,
  homeSymlinkNodes,
  uvHomeRoots,
} from "./sandbox-visible-paths.js";
import {
  buildMaskedCommandShimPlan,
  buildMaskedCommandShimPlanAsync,
  type MaskedCommandShimPlan,
} from "./masked-command-shim.js";
import { DEFAULT_SCAN_DURATION_MS } from "./scan-budget.js";
import { buildSrtNetworkPlanFromConfig, type SrtNetworkPlan } from "./srt-network-plan.js";
import type { UnmaskedPath, ResolvedSandboxProfile, SandboxConfig, SandboxResourceLimits } from "./types.js";

export interface SrtCommandSpecInput {
  command: string;
  cwd: string;
  repoRoot: string;
  sandboxConfig: SandboxConfig;
  profile: ResolvedSandboxProfile;
  unifiedConfig?: {
    network?: DomainGateConfig;
  };
  approvedDomains?: string[];
  unmaskedPaths?: UnmaskedPath[];
  secretEnv?: Record<string, string>;
}

export interface SrtCommandSpec {
  command: string;
  cwd: string;
  repoRoot: string;
  profileName: string;
  networkEnabled: boolean;
  allowDocker: boolean;
  roBinds: string[];
  rwBinds: string[];
  maskedPaths: string[];
  unmaskedPaths: UnmaskedPath[];
  secretEnvNames: string[];
  envAllowPatterns?: string[];
  envDenyPatterns: string[];
  resourceLimits?: SandboxResourceLimits;
  visibleReadPaths: string[];
  runtimeReadAllowPaths: string[];
  maskedShimPlan: MaskedCommandShimPlan;
  execShimPlan: Record<string, string>;
  networkPlan: SrtNetworkPlan;
}

const DARWIN_CLT_GIT = "/Library/Developer/CommandLineTools/usr/bin/git";

export function buildSrtExecShimPlan(
  platform: NodeJS.Platform = process.platform,
): Record<string, string> {
  if (platform !== "darwin") return {};
  return existsSync(DARWIN_CLT_GIT) ? { git: DARWIN_CLT_GIT } : {};
}

function filterMaskedScanRoots(scanRoots: string[], infrastructureRoots: string[]): string[] {
  const roots = infrastructureRoots.map(canonicalPath);
  const uvRoots = uvHomeRoots();
  return scanRoots.filter((scanRoot) =>
    !uvRoots.some((uvRoot) => scanRoot === uvRoot || scanRoot.startsWith(`${uvRoot}/`))
    && !roots.some((root) =>
      scanRoot === root ||
      scanRoot.startsWith(`${root}/`) ||
      root.startsWith(`${scanRoot}/`),
    ),
  );
}

function filterMaskedShimPlan(
  plan: MaskedCommandShimPlan,
  unmaskedPaths: UnmaskedPath[],
): MaskedCommandShimPlan {
  const approved = new Set(unmaskedPaths.map((entry) => canonicalPath(entry.path)));
  const maskedFilePaths = plan.maskedFilePaths.filter((path) => !approved.has(canonicalPath(path)));
  const maskedDenyPaths = plan.maskedDenyPaths.filter((path) => !approved.has(canonicalPath(path)));
  const shimCommands = maskedFilePaths.length === 0 ? [] : plan.shimCommands;
  return { maskedFilePaths, maskedDenyPaths, shimCommands };
}

async function filterMaskedShimPlanWithinScanBudget(
  plan: MaskedCommandShimPlan,
  unmaskedPaths: UnmaskedPath[],
  deadline: number,
  durationMs: number,
): Promise<MaskedCommandShimPlan> {
  const approved = new Set(await Promise.all(unmaskedPaths.map((entry) =>
    canonicalPathWithinScanBudget(entry.path, deadline, durationMs),
  )));
  const maskedFilePaths = (await Promise.all(plan.maskedFilePaths.map((filePath) =>
    canonicalPathWithinScanBudget(filePath, deadline, durationMs),
  ))).filter((filePath) => !approved.has(filePath));
  const maskedDenyPaths = (await Promise.all(plan.maskedDenyPaths.map((filePath) =>
    canonicalPathWithinScanBudget(filePath, deadline, durationMs),
  ))).filter((filePath) => !approved.has(filePath));
  const shimCommands = maskedFilePaths.length === 0 ? [] : plan.shimCommands;
  return { maskedFilePaths, maskedDenyPaths, shimCommands };
}

/** Adds home symlink nodes of logical allowed paths; masked scans keep the pre-link roots. */
function withHomeSymlinkNodes(
  readPaths: string[],
  input: SrtCommandSpecInput,
  resolvedBinds: string[],
): string[] {
  const logicalPaths = [...resolvedBinds, ...(input.unmaskedPaths ?? []).map((entry) => entry.path)];
  return [...new Set([...readPaths, ...logicalPaths.flatMap(homeSymlinkNodes)])];
}

export function buildSrtCommandSpec(input: SrtCommandSpecInput): SrtCommandSpec {
  const cwd = canonicalPath(input.cwd);
  const repoRoot = canonicalPath(input.repoRoot);
  const roBinds = resolveSandboxBindPaths(
    [...(input.sandboxConfig.roBinds ?? []), ...(input.profile.roBinds ?? [])],
    repoRoot,
  ).map(canonicalPath);
  const rwBinds = resolveSandboxBindPaths(
    [...(input.sandboxConfig.rwBinds ?? []), ...(input.profile.rwBinds ?? [])],
    repoRoot,
  ).map(canonicalPath);
  const resolvedBinds = [...roBinds, ...rwBinds, ...(input.sandboxConfig.infrastructureReadPaths ?? [])];
  const visibleReadPaths = buildSandboxVisiblePaths({
    repoRoot,
    cwd,
    command: input.command,
    profile: input.profile,
    config: input.sandboxConfig,
    resolvedBinds,
  });
  const readAllowPaths = buildSandboxRuntimeReadAllowPaths({
    repoRoot,
    cwd,
    command: input.command,
    profile: input.profile,
    config: input.sandboxConfig,
    resolvedBinds,
  });
  const runtimeReadAllowPaths = withHomeSymlinkNodes(readAllowPaths, input, resolvedBinds);

  const unmaskedPaths = (input.unmaskedPaths ?? []).map((entry) => ({
    ...entry,
    path: canonicalPath(entry.path),
  }));
  const maskedShimPlan = filterMaskedShimPlan(
    buildMaskedCommandShimPlan(input.command, input.profile, cwd, {
      scanRoots: filterMaskedScanRoots(
        readAllowPaths,
        input.sandboxConfig.infrastructureReadPaths ?? [],
      ),
    }),
    unmaskedPaths,
  );

  return {
    command: input.command,
    cwd,
    repoRoot,
    profileName: input.profile.name,
    networkEnabled: input.profile.network,
    allowDocker: input.profile.allowDocker === true,
    roBinds,
    rwBinds,
    maskedPaths: [...(input.profile.maskedPaths ?? [])],
    unmaskedPaths,
    secretEnvNames: Object.keys(input.secretEnv ?? {}),
    envAllowPatterns: [...(input.profile.env?.allow ?? [])],
    envDenyPatterns: [...(input.profile.env?.deny ?? [])],
    resourceLimits: input.profile.resourceLimits,
    visibleReadPaths,
    runtimeReadAllowPaths,
    maskedShimPlan,
    execShimPlan: buildSrtExecShimPlan(),
    networkPlan: buildSrtNetworkPlanFromConfig({
      sandboxNetworkEnabled: input.profile.network,
      config: input.unifiedConfig,
      cwd,
      approvedDomains: input.approvedDomains,
    }),
  };
}

export async function buildSrtCommandSpecAsync(
  input: SrtCommandSpecInput,
  maxScanDurationMs = DEFAULT_SCAN_DURATION_MS,
): Promise<SrtCommandSpec> {
  const deadline = Date.now() + maxScanDurationMs;
  const cwd = await canonicalPathWithinScanBudget(input.cwd, deadline, maxScanDurationMs);
  const repoRoot = await canonicalPathWithinScanBudget(input.repoRoot, deadline, maxScanDurationMs);
  const roBinds = await resolveSandboxBindPathsWithinScanBudget(
    [...(input.sandboxConfig.roBinds ?? []), ...(input.profile.roBinds ?? [])],
    repoRoot,
    deadline,
    maxScanDurationMs,
  );
  const rwBinds = await resolveSandboxBindPathsWithinScanBudget(
    [...(input.sandboxConfig.rwBinds ?? []), ...(input.profile.rwBinds ?? [])],
    repoRoot,
    deadline,
    maxScanDurationMs,
  );
  const resolvedBinds = [...roBinds, ...rwBinds, ...(input.sandboxConfig.infrastructureReadPaths ?? [])];
  const visibilityContext = {
    repoRoot,
    cwd,
    command: input.command,
    commandUsesUv: await commandContainsUvExecutable(input.command),
    profile: input.profile,
    config: input.sandboxConfig,
    resolvedBinds,
  };
  const visibleReadPaths = await buildSandboxVisiblePathsWithinScanBudget(
    visibilityContext,
    deadline,
    maxScanDurationMs,
  );
  const runtimeReadAllowPaths = withHomeSymlinkNodes(visibleReadPaths, input, resolvedBinds);
  const unmaskedPaths = await Promise.all((input.unmaskedPaths ?? []).map(async (entry) => ({
    ...entry,
    path: await canonicalPathWithinScanBudget(entry.path, deadline, maxScanDurationMs),
  })));
  const infrastructureRoots = await Promise.all(
    (input.sandboxConfig.infrastructureReadPaths ?? []).map((root) =>
      canonicalPathWithinScanBudget(root, deadline, maxScanDurationMs),
    ),
  );
  const maskedShimPlan = await filterMaskedShimPlanWithinScanBudget(
    await buildMaskedCommandShimPlanAsync(input.command, input.profile, cwd, {
      scanRoots: filterMaskedScanRoots(visibleReadPaths, infrastructureRoots),
      deadline,
      maxScanDurationMs,
    }),
    unmaskedPaths,
    deadline,
    maxScanDurationMs,
  );

  return {
    command: input.command,
    cwd,
    repoRoot,
    profileName: input.profile.name,
    networkEnabled: input.profile.network,
    allowDocker: input.profile.allowDocker === true,
    roBinds,
    rwBinds,
    maskedPaths: [...(input.profile.maskedPaths ?? [])],
    unmaskedPaths,
    secretEnvNames: Object.keys(input.secretEnv ?? {}),
    envAllowPatterns: [...(input.profile.env?.allow ?? [])],
    envDenyPatterns: [...(input.profile.env?.deny ?? [])],
    resourceLimits: input.profile.resourceLimits,
    visibleReadPaths,
    runtimeReadAllowPaths,
    maskedShimPlan,
    execShimPlan: buildSrtExecShimPlan(),
    networkPlan: buildSrtNetworkPlanFromConfig({
      sandboxNetworkEnabled: input.profile.network,
      config: input.unifiedConfig,
      cwd,
      approvedDomains: input.approvedDomains,
    }),
  };
}
