import { describe, expect, it, vi } from "vitest";
import { createSandboxRuntimeLoader } from "./runtime-lazy.js";

describe("createSandboxRuntimeLoader", () => {
  it("defers runtime construction until first getRuntime", () => {
    const loadConfig = vi.fn(() => ({ network: { enabled: true } as never, sandbox: { enabled: true } }));
    const normalizeSandboxConfig = vi.fn((raw) => ({ enabled: Boolean((raw as { enabled?: boolean })?.enabled) } as never));
    const createPolicyManager = vi.fn(() => ({ id: "pm", updateConfig: vi.fn() } as never));
    const createBackend = vi.fn(() => ({ kind: "bwrap" } as never));

    const loader = createSandboxRuntimeLoader({
      loadConfig,
      normalizeSandboxConfig,
      createPolicyManager,
      createBackend,
    });

    expect(loadConfig).not.toHaveBeenCalled();
    expect(normalizeSandboxConfig).not.toHaveBeenCalled();
    expect(createPolicyManager).not.toHaveBeenCalled();
    expect(createBackend).not.toHaveBeenCalled();

    const runtime = loader.getRuntime();

    expect(loadConfig).toHaveBeenCalledTimes(1);
    expect(normalizeSandboxConfig).toHaveBeenCalledTimes(1);
    expect(createPolicyManager).toHaveBeenCalledTimes(1);
    expect(createBackend).toHaveBeenCalledTimes(1);
    expect(createBackend).toHaveBeenCalledWith({ enabled: true });
    expect(runtime.policyManager).toEqual(expect.objectContaining({ id: "pm" }));
    expect(runtime.backend).toEqual({ kind: "bwrap" });
  });

  it("memoizes runtime across calls", () => {
    const loadConfig = vi.fn(() => ({ network: undefined, sandbox: {} }));
    const normalizeSandboxConfig = vi.fn(() => ({ enabled: false } as never));
    const createPolicyManager = vi.fn(() => ({ id: "pm", updateConfig: vi.fn() } as never));
    const createBackend = vi.fn(() => ({ kind: "bwrap" } as never));

    const loader = createSandboxRuntimeLoader({
      loadConfig,
      normalizeSandboxConfig,
      createPolicyManager,
      createBackend,
    });

    const a = loader.getRuntime();
    const b = loader.getRuntime();

    expect(a).toBe(b);
    expect(loadConfig).toHaveBeenCalledTimes(1);
    expect(normalizeSandboxConfig).toHaveBeenCalledTimes(1);
    expect(createPolicyManager).toHaveBeenCalledTimes(1);
    expect(createBackend).toHaveBeenCalledTimes(1);
    expect(createBackend).toHaveBeenCalledWith({ enabled: false });
  });

  it("clears grants without constructing an unused runtime", () => {
    const clearGrants = vi.fn();
    const loadConfig = vi.fn(() => ({ network: undefined, sandbox: {} }));
    const policyManager = { clearGrants, updateConfig: vi.fn() } as never;
    const loader = createSandboxRuntimeLoader({
      loadConfig,
      normalizeSandboxConfig: vi.fn(() => ({ enabled: false } as never)),
      createPolicyManager: vi.fn(() => policyManager),
      createBackend: vi.fn(() => ({ kind: "bwrap" } as never)),
    });

    loader.clearGrants();
    expect(clearGrants).not.toHaveBeenCalled();

    loader.getRuntime();
    loader.clearGrants();
    expect(clearGrants).toHaveBeenCalledTimes(1);
  });

  it("disposes policy manager and allows fresh runtime construction", () => {
    const destroy = vi.fn();
    const policyManager = { destroy, updateConfig: vi.fn() } as never;
    const createPolicyManager = vi.fn(() => policyManager);
    const loader = createSandboxRuntimeLoader({
      loadConfig: vi.fn(() => ({ network: undefined, sandbox: {} })),
      normalizeSandboxConfig: vi.fn(() => ({ enabled: false } as never)),
      createPolicyManager,
      createBackend: vi.fn(() => ({ kind: "bwrap" } as never)),
    });

    loader.getRuntime();
    loader.dispose();
    loader.getRuntime();

    expect(destroy).toHaveBeenCalledTimes(1);
    expect(createPolicyManager).toHaveBeenCalledTimes(2);
  });

  it("reloads network and sandbox config into existing runtime and recreates backend", () => {
    const loadConfig = vi
      .fn<() => { network?: unknown; sandbox?: unknown }>()
      .mockReturnValueOnce({ network: { enabled: true }, sandbox: { enabled: true } })
      .mockReturnValueOnce({ network: { enabled: false }, sandbox: { enabled: false, backend: "srt" } });
    const normalizeSandboxConfig = vi
      .fn((raw) => ({
        enabled: Boolean((raw as { enabled?: boolean })?.enabled),
        backend: (raw as { backend?: string })?.backend ?? "bwrap",
      } as never));
    const policyManager = { id: "pm", updateConfig: vi.fn() } as never;
    const createPolicyManager = vi.fn(() => policyManager);
    const createBackend = vi
      .fn()
      .mockReturnValueOnce({ kind: "bwrap" } as never)
      .mockReturnValueOnce({ kind: "srt" } as never);

    const loader = createSandboxRuntimeLoader({
      loadConfig,
      normalizeSandboxConfig,
      createPolicyManager,
      createBackend,
    });

    const runtime = loader.getRuntime();
    const reloaded = loader.reloadConfig();

    expect(reloaded).toBe(runtime);
    expect(runtime.networkConfig).toEqual({ enabled: false });
    expect(runtime.sandboxConfig).toEqual({ enabled: false, backend: "srt" });
    expect(runtime.backend).toEqual({ kind: "srt" });
    expect(policyManager.updateConfig).toHaveBeenCalledWith({ enabled: false, backend: "srt" });
    expect(createPolicyManager).toHaveBeenCalledTimes(1);
    expect(createBackend).toHaveBeenCalledTimes(2);
    expect(createBackend).toHaveBeenNthCalledWith(1, { enabled: true, backend: "bwrap" });
    expect(createBackend).toHaveBeenNthCalledWith(2, { enabled: false, backend: "srt" });
  });
});
