import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { getLegacyGlobalPolicyPath } from "./config-paths";
import { resetExtensionConfig, saveExtensionConfig, saveSandboxEnabled } from "./runtime";

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("saveExtensionConfig", () => {
  it("preserves unrelated global config sections", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-config-"));
    tempPaths.push(agentDir);
    await writeFile(
      path.join(agentDir, "permissions.json"),
      JSON.stringify({
        network: { allowedDomains: ["example.com"] },
        sandbox: { enabled: true },
        permission: { write: "deny" },
        mode: "manual",
        yoloAutoMaxLevel: "l2",
      }),
      "utf8",
    );

    const runtime = {
      agentDir,
      writeDebugLog: vi.fn(),
    };
    const ctx = {
      ui: { setStatus: vi.fn(), notify: vi.fn() },
    };

    saveExtensionConfig(
      runtime as never,
      {
        debugLog: true,
        permissionReviewLog: true,
        mode: "yolo",
        yoloAskBashPatterns: ["git push *"],
      },
      ctx as never,
    );

    const saved = JSON.parse(
      await readFile(path.join(agentDir, "permissions.json"), "utf8"),
    );
    expect(saved).toMatchObject({
      network: { allowedDomains: ["example.com"] },
      sandbox: { enabled: true },
      permission: { write: "deny" },
      debugLog: true,
      mode: "yolo",
    });
    expect(saved).not.toHaveProperty("yoloAutoMaxLevel");
  });

  it("does not persist the process mode override when saving another setting", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-mode-override-"));
    const projectDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-mode-project-"));
    tempPaths.push(agentDir, projectDir);
    const configPath = path.join(agentDir, "permissions.json");
    await writeFile(
      getLegacyGlobalPolicyPath(agentDir),
      JSON.stringify({ yoloMode: false, yoloAutoMode: false }),
      "utf8",
    );
    await writeFile(configPath, JSON.stringify({ yoloMode: false }), "utf8");

    const previousMode = process.env.PI_SENTINEL_MODE;
    process.env.PI_SENTINEL_MODE = "yolo";
    try {
      const runtime = {
        agentDir,
        runtimeContext: { cwd: projectDir },
        config: { mode: "yolo" },
        writeDebugLog: vi.fn(),
      };
      const ctx = {
        cwd: projectDir,
        ui: { setStatus: vi.fn(), notify: vi.fn() },
      };

      saveExtensionConfig(
        runtime as never,
        {
          debugLog: true,
          permissionReviewLog: true,
          mode: "yolo",
          yoloAskBashPatterns: [],
        },
        ctx as never,
      );

      const saved = JSON.parse(await readFile(configPath, "utf8"));
      expect(saved.mode).toBe("manual");
      expect(runtime.config).toMatchObject({ mode: "yolo" });
    } finally {
      if (previousMode === undefined) delete process.env.PI_SENTINEL_MODE;
      else process.env.PI_SENTINEL_MODE = previousMode;
    }
  });

  it("persists an explicit mode choice that matches the process override", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-matching-mode-"));
    const projectDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-matching-mode-project-"));
    tempPaths.push(agentDir, projectDir);
    const configPath = path.join(agentDir, "permissions.json");
    await writeFile(configPath, JSON.stringify({ mode: "manual" }), "utf8");

    const previousMode = process.env.PI_SENTINEL_MODE;
    process.env.PI_SENTINEL_MODE = "yolo";
    try {
      const runtime = {
        agentDir,
        runtimeContext: { cwd: projectDir },
        config: { mode: "yolo" },
        writeDebugLog: vi.fn(),
      };
      const ctx = {
        cwd: projectDir,
        ui: { setStatus: vi.fn(), notify: vi.fn() },
      };

      saveExtensionConfig(
        runtime as never,
        {
          debugLog: true,
          permissionReviewLog: true,
          mode: "yolo",
          yoloAskBashPatterns: [],
        },
        ctx as never,
        true,
      );

      expect(JSON.parse(await readFile(configPath, "utf8")).mode).toBe("yolo");
      expect(runtime.config).toMatchObject({ mode: "yolo" });
    } finally {
      if (previousMode === undefined) delete process.env.PI_SENTINEL_MODE;
      else process.env.PI_SENTINEL_MODE = previousMode;
    }
  });

  it("persists an explicit mode change while keeping the process override active", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-explicit-mode-"));
    const projectDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-explicit-mode-project-"));
    tempPaths.push(agentDir, projectDir);
    const configPath = path.join(agentDir, "permissions.json");
    await writeFile(configPath, JSON.stringify({ mode: "yolo-auto" }), "utf8");

    const previousMode = process.env.PI_SENTINEL_MODE;
    process.env.PI_SENTINEL_MODE = "yolo";
    try {
      const runtime = {
        agentDir,
        runtimeContext: { cwd: projectDir },
        config: { mode: "yolo" },
        writeDebugLog: vi.fn(),
      };
      const ctx = {
        cwd: projectDir,
        ui: { setStatus: vi.fn(), notify: vi.fn() },
      };

      saveExtensionConfig(
        runtime as never,
        {
          debugLog: true,
          permissionReviewLog: true,
          mode: "manual",
          yoloAskBashPatterns: [],
        },
        ctx as never,
        true,
      );

      expect(JSON.parse(await readFile(configPath, "utf8")).mode).toBe("manual");
      expect(runtime.config).toMatchObject({ mode: "yolo" });
    } finally {
      if (previousMode === undefined) delete process.env.PI_SENTINEL_MODE;
      else process.env.PI_SENTINEL_MODE = previousMode;
    }
  });

  it("keeps project runtime overrides after global reset", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-reset-global-"));
    const projectDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-reset-project-"));
    tempPaths.push(agentDir, projectDir);
    await writeFile(
      path.join(agentDir, "permissions.json"),
      JSON.stringify({ yoloMode: false }),
      "utf8",
    );
    const projectPath = path.join(projectDir, ".pi", "agent", "permissions.json");
    await mkdir(path.dirname(projectPath), { recursive: true });
    await writeFile(projectPath, JSON.stringify({ yoloMode: true }), "utf8");

    const runtime = {
      agentDir,
      runtimeContext: { cwd: projectDir },
      config: {},
      lastConfigWarning: null,
      writeDebugLog: vi.fn(),
    };
    const ctx = {
      cwd: projectDir,
      ui: { setStatus: vi.fn(), notify: vi.fn() },
    };

    resetExtensionConfig(runtime as never, ctx as never);

    expect(runtime.config).toMatchObject({ mode: "yolo-auto" });
  });

  it("removes runtime overrides so bundled defaults become effective", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-runtime-reset-"));
    tempPaths.push(agentDir);
    const configPath = path.join(agentDir, "permissions.json");
    await writeFile(
      configPath,
      JSON.stringify({
        debugLog: true,
        permissionReviewLog: false,
        mode: "yolo",
        yoloAskBashPatterns: ["git push *"],
        network: { allowedDomains: ["example.com"] },
      }),
      "utf8",
    );

    const runtime = {
      agentDir,
      config: {},
      lastConfigWarning: "old warning",
      writeDebugLog: vi.fn(),
    };
    const ctx = {
      ui: { setStatus: vi.fn(), notify: vi.fn() },
    };

    resetExtensionConfig(runtime as never, ctx as never);

    const saved = JSON.parse(await readFile(configPath, "utf8"));
    expect(saved).toEqual({ network: { allowedDomains: ["example.com"] } });
    expect(runtime.config).toMatchObject({
      debugLog: false,
      permissionReviewLog: true,
      mode: "yolo-auto",
      yoloAskBashPatterns: [],
    });
  });
});

describe("saveSandboxEnabled", () => {
  it("preserves effective legacy mode while toggling sandbox", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-sandbox-mode-"));
    tempPaths.push(agentDir);
    const configPath = path.join(agentDir, "permissions.json");
    await writeFile(
      getLegacyGlobalPolicyPath(agentDir),
      JSON.stringify({ yoloMode: false, yoloAutoMode: false }),
      "utf8",
    );
    await writeFile(
      configPath,
      JSON.stringify({ yoloMode: false, sandbox: { enabled: true } }),
      "utf8",
    );

    const previousMode = process.env.PI_SENTINEL_MODE;
    process.env.PI_SENTINEL_MODE = "yolo";
    try {
      const ctx = { ui: { setStatus: vi.fn(), notify: vi.fn() } };
      expect(saveSandboxEnabled({ agentDir, writeDebugLog: vi.fn() } as never, false, ctx as never)).toBe(true);

      const saved = JSON.parse(await readFile(configPath, "utf8"));
      expect(saved.mode).toBe("manual");
      expect(saved.sandbox).toMatchObject({ enabled: false });
    } finally {
      if (previousMode === undefined) delete process.env.PI_SENTINEL_MODE;
      else process.env.PI_SENTINEL_MODE = previousMode;
    }
  });

  it("toggles sandbox.enabled and keeps other sandbox keys", async () => {
    const agentDir = await mkdtemp(path.join(tmpdir(), "pi-sandbox-toggle-"));
    tempPaths.push(agentDir);
    const file = path.join(agentDir, "permissions.json");
    await writeFile(file, JSON.stringify({ mode: "yolo", sandbox: { enabled: true, network: true, roBinds: ["a"] } }), "utf8");
    const ctx = { ui: { setStatus: vi.fn(), notify: vi.fn() } };

    expect(saveSandboxEnabled({ agentDir, writeDebugLog: vi.fn() } as never, false, ctx as never)).toBe(true);

    expect(JSON.parse(await readFile(file, "utf8"))).toEqual({ mode: "yolo", sandbox: { enabled: false, network: true, roBinds: ["a"] } });
  });
});
