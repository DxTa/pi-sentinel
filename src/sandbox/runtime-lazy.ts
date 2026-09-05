import type { DomainGateConfig } from "#src/network/config.js";
import type { SandboxBackend } from "#src/sandbox/backend.js";
import type { SandboxConfig } from "#src/sandbox/settings.js";
import type { SandboxPolicyManager } from "#src/sandbox/policy-manager.js";

export interface UnifiedConfigLike {
  network?: DomainGateConfig;
  sandbox?: Record<string, unknown>;
}

export interface SandboxRuntime {
  networkConfig: DomainGateConfig | undefined;
  sandboxConfig: SandboxConfig;
  policyManager: SandboxPolicyManager;
  backend: SandboxBackend;
}

export interface SandboxRuntimeDeps {
  loadConfig: () => UnifiedConfigLike;
  normalizeSandboxConfig: (raw: UnifiedConfigLike["sandbox"]) => SandboxConfig;
  createPolicyManager: (config: SandboxConfig) => SandboxPolicyManager;
  createBackend: (config: SandboxConfig) => SandboxBackend;
}

export function createSandboxRuntimeLoader(deps: SandboxRuntimeDeps) {
  let runtime: SandboxRuntime | null = null;

  function createRuntimeFromConfig(config: UnifiedConfigLike): SandboxRuntime {
    const sandboxConfig = deps.normalizeSandboxConfig(config.sandbox);
    const policyManager = deps.createPolicyManager(sandboxConfig);
    const backend = deps.createBackend(sandboxConfig);
    return {
      networkConfig: config.network,
      sandboxConfig,
      policyManager,
      backend,
    };
  }

  function getRuntime(): SandboxRuntime {
    if (runtime) return runtime;
    runtime = createRuntimeFromConfig(deps.loadConfig());
    return runtime;
  }

  function clearGrants(): void {
    runtime?.policyManager.clearGrants();
  }

  function reloadConfig(): SandboxRuntime {
    const config = deps.loadConfig();
    const sandboxConfig = deps.normalizeSandboxConfig(config.sandbox);

    if (!runtime) {
      runtime = createRuntimeFromConfig(config);
      return runtime;
    }

    runtime.networkConfig = config.network;
    runtime.sandboxConfig = sandboxConfig;
    runtime.policyManager.updateConfig(sandboxConfig);
    runtime.backend = deps.createBackend(sandboxConfig);
    return runtime;
  }

  function dispose(): void {
    runtime?.policyManager.destroy();
    runtime = null;
  }

  function resetForTesting(): void {
    dispose();
  }

  return {
    getRuntime,
    reloadConfig,
    clearGrants,
    dispose,
    resetForTesting,
  };
}
