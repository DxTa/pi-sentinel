import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  loadAndMergeConfigs,
  mergeUnifiedConfigs,
  normalizeUnifiedConfig,
} from "./config-loader";
import { getGlobalConfigPath, getProjectConfigPath } from "./config-paths";
import {
  DEFAULT_EXTENSION_CONFIG,
  EXTENSION_ROOT,
  normalizePermissionSystemConfig,
} from "./extension-config";
import { normalizeSandboxConfig } from "./sandbox/settings";

describe("permission mode config", () => {
  it("normalizes one explicit mode", () => {
    expect(normalizeUnifiedConfig({ mode: "manual" }).config).toEqual({ mode: "manual" });
    expect(normalizeUnifiedConfig({
      mode: "yolo-auto",
      yoloAutoMaxLevel: "l2",
    }).config).toMatchObject({
      mode: "yolo-auto",
      yoloAutoMaxLevel: "l2",
    });
    expect(normalizeUnifiedConfig({ mode: "invalid" }).config).toEqual({});
    expect(normalizeUnifiedConfig({ mode: "manual", yoloAutoMode: true }).config).toEqual({ mode: "manual" });
  });

  it("migrates legacy boolean modes without exposing them", () => {
    expect(normalizeUnifiedConfig({ yoloAutoMode: true }).config).toEqual({ mode: "yolo-auto" });
    expect(normalizeUnifiedConfig({ yoloMode: true }).config).toEqual({ mode: "yolo" });
    expect(normalizeUnifiedConfig({ yoloMode: true, yoloAutoMode: true }).config).toEqual({ mode: "yolo-auto" });
    expect(normalizeUnifiedConfig({ yoloAutoMode: false }).config).toEqual({ mode: "manual" });
  });

  it("keeps inherited auto behavior when legacy yoloMode is partial", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "pi-legacy-mode-"));
    tempPaths.push(root);
    const agentDir = path.join(root, "agent");
    const projectDir = path.join(root, "project");
    const extensionRoot = path.join(root, "extension");
    await Promise.all([agentDir, projectDir, extensionRoot].map((dir) => mkdir(dir, { recursive: true })));
    await writeFile(path.join(extensionRoot, "config.json"), JSON.stringify({ mode: "yolo-auto" }), "utf8");
    await mkdir(path.dirname(getGlobalConfigPath(agentDir)), { recursive: true });
    await writeFile(getGlobalConfigPath(agentDir), JSON.stringify({ yoloMode: true }), "utf8");

    expect(loadAndMergeConfigs(agentDir, projectDir, extensionRoot).merged).toMatchObject({
      mode: "yolo-auto",
    });
  });

  it("lets project mode replace global mode", () => {
    expect(mergeUnifiedConfigs(
      { mode: "yolo-auto", yoloAutoMaxLevel: "l2" },
      { mode: "manual" },
    )).toMatchObject({
      mode: "manual",
      yoloAutoMaxLevel: "l2",
    });
  });

  it("accepts L3 as yolo-auto ceiling", () => {
    const normalized = normalizeUnifiedConfig({
      mode: "yolo-auto",
      yoloAutoMaxLevel: "l3",
    }).config;

    expect(normalized).toMatchObject({ mode: "yolo-auto", yoloAutoMaxLevel: "l3" });
  });

  it("parses string arrays from unified config", () => {
    const { config } = normalizeUnifiedConfig({
      yoloAskBashPatterns: ["git push *", "git commit *"],
    });

    expect(config).toMatchObject({
      yoloAskBashPatterns: ["git push *", "git commit *"],
    });
  });

  it("filters non-string entries and ignores non-array values", () => {
    const filtered = normalizeUnifiedConfig({
      yoloAskBashPatterns: ["git push *", 123, null, "git commit *"],
    }).config;
    const ignored = normalizeUnifiedConfig({
      yoloAskBashPatterns: "git push *",
    }).config;

    expect(filtered).toMatchObject({
      yoloAskBashPatterns: ["git push *", "git commit *"],
    });
    expect(ignored).not.toHaveProperty("yoloAskBashPatterns");
  });

  it("lets override replace inherited pattern list", () => {
    const merged = mergeUnifiedConfigs(
      { yoloAskBashPatterns: ["git push *"] } as any,
      { yoloAskBashPatterns: ["git commit *"] } as any,
    );

    expect(merged).toMatchObject({
      yoloAskBashPatterns: ["git commit *"],
    });
  });

  it("defaults extension runtime config to empty list", () => {
    expect(DEFAULT_EXTENSION_CONFIG).toMatchObject({
      mode: "yolo-auto",
      yoloAutoMaxLevel: "l3",
      yoloAskBashPatterns: [],
    });
    expect(normalizePermissionSystemConfig({})).toMatchObject({
      yoloAskBashPatterns: [],
    });
  });

  it("ships enabled SRT sandbox with online-dev network mode", async () => {
    const bundled = JSON.parse(
      await readFile(path.join(EXTENSION_ROOT, "config.json"), "utf8"),
    ) as { sandbox?: unknown };
    const sandbox = normalizeSandboxConfig(bundled.sandbox);

    expect(sandbox).toMatchObject({
      enabled: true,
      backend: "srt",
      defaultProfile: "online-dev",
    });
    expect(sandbox.profiles["online-dev"]?.network).toBe(true);
  });
});

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("layered permission config paths", () => {
  it("uses permissions.json paths and applies bundled, global, then project precedence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "pi-layered-config-"));
    tempPaths.push(root);
    const agentDir = path.join(root, "agent");
    const projectDir = path.join(root, "project");
    const extensionRoot = path.join(root, "extension");
    await Promise.all([agentDir, projectDir, extensionRoot].map((dir) => mkdir(dir, { recursive: true })));

    await writeFile(
      path.join(extensionRoot, "config.json"),
      JSON.stringify({
        mode: "manual",
        permission: {
          bash: { "git *": "ask" },
        },
      }),
      "utf8",
    );
    const globalPath = getGlobalConfigPath(agentDir);
    await mkdir(path.dirname(globalPath), { recursive: true });
    await writeFile(
      globalPath,
      JSON.stringify({
        mode: "yolo",
        permission: {
          bash: { "git push *": "allow" },
        },
      }),
      "utf8",
    );
    const projectPath = getProjectConfigPath(projectDir);
    await mkdir(path.dirname(projectPath), { recursive: true });
    await writeFile(
      projectPath,
      JSON.stringify({
        mode: "manual",
        permission: {
          bash: { "git push *": "deny" },
        },
      }),
      "utf8",
    );

    const result = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);

    expect(getGlobalConfigPath("/agent")).toBe("/agent/permissions.json");
    expect(getProjectConfigPath("/repo")).toBe("/repo/.pi/permissions.json");
    expect(result.issues).toEqual([]);
    expect(result.merged).toMatchObject({
      mode: "manual",
      permission: {
        bash: {
          "git *": "ask",
          "git push *": "deny",
        },
      },
    });
  });
});
