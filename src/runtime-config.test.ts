import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { resetExtensionConfig, saveExtensionConfig } from "./runtime";

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
        yoloMode: false,
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
        yoloMode: true,
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
      yoloMode: true,
    });
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

    expect(runtime.config).toMatchObject({ yoloMode: true });
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
        yoloMode: true,
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
      yoloMode: false,
      yoloAskBashPatterns: [],
    });
  });
});
