import { loadDomainPolicy, type DomainGateConfig, type ResolvedDomainPolicy } from "#src/network/config.js";

export interface SrtNetworkPlanInput {
  sandboxNetworkEnabled: boolean;
  domainPolicy: ResolvedDomainPolicy;
  approvedDomains?: string[];
}

export interface SrtNetworkPlanFromConfigInput {
  sandboxNetworkEnabled: boolean;
  config: { network?: DomainGateConfig } | undefined;
  cwd: string;
  approvedDomains?: string[];
}

export interface SrtNetworkRuntimeConfig {
  allowedDomains: string[];
  deniedDomains: string[];
  strictAllowlist: boolean;
}

export type SrtUnmatchedHostAction = "allow" | "deny";

export interface RuntimeFilteredSrtNetworkPlan {
  mode: "runtime-filtered";
  requiresOuterPrompt: boolean;
  unmatchedHostAction: SrtUnmatchedHostAction;
  config: SrtNetworkRuntimeConfig;
}

export type SrtNetworkPlan = RuntimeFilteredSrtNetworkPlan;

function dedupe(values: string[] | undefined): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const raw of values ?? []) {
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }
  return result;
}

function expandPatternForSrt(pattern: string): string[] {
  if (pattern === "*") return [pattern];
  if (pattern.startsWith("*.")) {
    return [pattern.slice(2), pattern];
  }
  return [pattern];
}

function resolveAllowedDomains(
  values: string[],
): { allowedDomains: string[]; hasAllowAll: boolean } {
  const normalized = dedupe(values);
  const expanded = normalized.flatMap(expandPatternForSrt);
  const hasAllowAll = expanded.includes("*");
  return {
    allowedDomains: hasAllowAll ? expanded.filter((value) => value !== "*") : dedupe(expanded),
    hasAllowAll,
  };
}

function resolveDeniedDomains(
  values: string[],
): { deniedDomains: string[]; hasDenyAll: boolean } {
  const normalized = dedupe(values);
  const hasDenyAll = normalized.includes("*");
  if (hasDenyAll) {
    return { deniedDomains: [], hasDenyAll: true };
  }
  return {
    deniedDomains: dedupe(normalized.flatMap(expandPatternForSrt)),
    hasDenyAll: false,
  };
}

export function buildSrtNetworkPlanFromConfig(
  input: SrtNetworkPlanFromConfigInput,
): SrtNetworkPlan {
  const domainPolicy = loadDomainPolicy(input.config);
  return buildSrtNetworkPlan({
    sandboxNetworkEnabled: input.sandboxNetworkEnabled,
    domainPolicy,
    approvedDomains: input.approvedDomains,
  });
}

export function buildSrtNetworkPlan(
  input: SrtNetworkPlanInput,
): SrtNetworkPlan {
  if (!input.sandboxNetworkEnabled) {
    return {
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: [],
        deniedDomains: [],
        strictAllowlist: true,
      },
    };
  }

  if (!input.domainPolicy.enabled) {
    const { deniedDomains, hasDenyAll } = resolveDeniedDomains(
      input.domainPolicy.deniedDomains,
    );
    return {
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: hasDenyAll ? "deny" : "allow",
      config: {
        allowedDomains: [],
        deniedDomains: hasDenyAll ? [] : deniedDomains,
        strictAllowlist: hasDenyAll,
      },
    };
  }

  const { allowedDomains, hasAllowAll } = resolveAllowedDomains([
    ...input.domainPolicy.allowedDomains,
    ...(input.approvedDomains ?? []),
  ]);
  const { deniedDomains, hasDenyAll } = resolveDeniedDomains(
    input.domainPolicy.deniedDomains,
  );

  if (hasDenyAll) {
    return {
      mode: "runtime-filtered",
      requiresOuterPrompt: false,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: [],
        deniedDomains: [],
        strictAllowlist: true,
      },
    };
  }

  const unknownDomains = input.domainPolicy.unknownDomains;
  const unmatchedHostAction: SrtUnmatchedHostAction =
    hasAllowAll || unknownDomains === "allow" ? "allow" : "deny";

  return {
    mode: "runtime-filtered",
    requiresOuterPrompt: unknownDomains === "ask",
    unmatchedHostAction,
    config: {
      allowedDomains,
      deniedDomains,
      strictAllowlist: unmatchedHostAction === "deny",
    },
  };
}
