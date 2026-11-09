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
    const legacy = normalizeUnifiedConfig({
      mode: "auto",
      yoloAutoMaxLevel: "l2",
    });
    expect(legacy.config).toEqual({ mode: "auto" });
    expect(legacy.issues).toHaveLength(1);
    expect(legacy.issues[0]).toContain("yoloAutoMaxLevel");
    expect(normalizeUnifiedConfig({ mode: "invalid" }).config).toEqual({});
    expect(normalizeUnifiedConfig({ mode: "manual", yoloAutoMode: true }).config).toEqual({ mode: "manual" });
  });

  it("rejects the removed yolo-auto mode name", () => {
    const result = normalizeUnifiedConfig({ mode: "yolo-auto" });
    expect(result.config).toEqual({});
    expect(result.issues).toEqual([
      "Ignoring invalid mode \"yolo-auto\"; expected 'manual', 'yolo', or 'auto'.",
    ]);
    expect(normalizePermissionSystemConfig({ mode: "yolo-auto" }).mode).toBe("manual");
  });

  it("lets project mode replace global mode", () => {
    expect(mergeUnifiedConfigs(
      { mode: "auto" },
      { mode: "manual" },
    )).toEqual({ mode: "manual" });
  });

  it("overrides only the merged mode and reports invalid PI_SENTINEL_MODE values", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "pi-mode-env-"));
    tempPaths.push(root);
    const agentDir = path.join(root, "agent");
    const projectDir = path.join(root, "project");
    const extensionRoot = path.join(root, "extension");
    await mkdir(extensionRoot, { recursive: true });
    await writeFile(
      path.join(extensionRoot, "config.json"),
      JSON.stringify({ mode: "manual" }),
      "utf8",
    );

    const previousMode = process.env.PI_SENTINEL_MODE;
    process.env.PI_SENTINEL_MODE = "yolo";
    try {
      const result = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);

      expect(result).toMatchObject({
        global: {},
        project: {},
        merged: { mode: "yolo" },
        configuredMode: "manual",
      });

      process.env.PI_SENTINEL_MODE = "unsafe";
      const invalidResult = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);
      expect(invalidResult.merged.mode).toBe("manual");
      expect(invalidResult.issues).toContain(
        "Ignoring invalid PI_SENTINEL_MODE; expected 'manual', 'yolo', or 'auto'.",
      );
    } finally {
      if (previousMode === undefined) delete process.env.PI_SENTINEL_MODE;
      else process.env.PI_SENTINEL_MODE = previousMode;
    }
  });

  it("warns once and drops the removed setting across config layers", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "pi-removed-yolo-level-"));
    tempPaths.push(root);
    const agentDir = path.join(root, "agent");
    const projectDir = path.join(root, "project");
    const extensionRoot = path.join(root, "extension");
    await Promise.all([agentDir, projectDir, extensionRoot].map((dir) => mkdir(dir, { recursive: true })));
    await writeFile(path.join(extensionRoot, "config.json"), JSON.stringify({ yoloAutoMaxLevel: "l3" }), "utf8");
    const globalPath = getGlobalConfigPath(agentDir);
    await mkdir(path.dirname(globalPath), { recursive: true });
    await writeFile(globalPath, JSON.stringify({ yoloAutoMaxLevel: "l2" }), "utf8");
    const projectPath = getProjectConfigPath(projectDir);
    await mkdir(path.dirname(projectPath), { recursive: true });
    await writeFile(projectPath, JSON.stringify({ yoloAutoMaxLevel: "l1" }), "utf8");

    const loaded = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);
    expect(loaded.merged).not.toHaveProperty("yoloAutoMaxLevel");
    expect(loaded.issues.filter((issue) => issue.includes("yoloAutoMaxLevel"))).toHaveLength(1);
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
      mode: "auto",
      yoloAskBashPatterns: [],
    });
    expect(DEFAULT_EXTENSION_CONFIG).not.toHaveProperty("yoloAutoMaxLevel");
    expect(normalizePermissionSystemConfig({})).toMatchObject({
      yoloAskBashPatterns: [],
    });
    expect(normalizePermissionSystemConfig({ yoloAutoMaxLevel: "l1" }))
      .not.toHaveProperty("yoloAutoMaxLevel");
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
  it("uses sentinel.json paths and applies bundled, global, then project precedence", async () => {
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

    expect(getGlobalConfigPath("/agent")).toBe("/agent/sentinel.json");
    expect(getProjectConfigPath("/repo")).toBe("/repo/.pi/sentinel.json");
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

describe("retired config files", () => {
  async function setupLayout(files: Record<string, unknown>): Promise<{
    agentDir: string;
    projectDir: string;
    extensionRoot: string;
  }> {
    const root = await mkdtemp(path.join(tmpdir(), "pi-retired-config-"));
    tempPaths.push(root);
    const agentDir = path.join(root, "agent");
    const projectDir = path.join(root, "project");
    const extensionRoot = path.join(root, "extension");
    await Promise.all([agentDir, projectDir, extensionRoot].map((dir) => mkdir(dir, { recursive: true })));
    await writeFile(path.join(extensionRoot, "config.json"), JSON.stringify({ mode: "manual" }), "utf8");
    for (const [relativePath, content] of Object.entries(files)) {
      const absolute = path.join(root, relativePath);
      await mkdir(path.dirname(absolute), { recursive: true });
      await writeFile(absolute, JSON.stringify(content), "utf8");
    }
    return {
      agentDir,
      projectDir,
      extensionRoot,
    };
  }

  it("ignores every retired config file location", async () => {
    const { agentDir, projectDir, extensionRoot } = await setupLayout({
      "agent/pi-permissions.jsonc": { mode: "yolo" },
      "project/.pi/agent/permissions.json": { mode: "yolo" },
      "project/.pi/extensions/pi-sentinel/config.json": { mode: "yolo" },
      "project/.pi/agent/pi-permissions.jsonc": { mode: "yolo" },
    });

    const result = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);

    expect(result.merged.mode).toBe("manual");
    expect(result.modeLayers.map((layer) => layer.id)).toEqual([
      "environment",
      "project",
      "global",
      "bundled",
    ]);
  });

  it("ignores legacy yoloMode and yoloAutoMode flags", async () => {
    const { agentDir, projectDir, extensionRoot } = await setupLayout({
      "agent/sentinel.json": { yoloMode: true, yoloAutoMode: true },
    });

    const result = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);

    expect(result.merged.mode).toBe("manual");
  });

  it("warns once per scope when permissions.json has no sentinel.json replacement", async () => {
    const { agentDir, projectDir, extensionRoot } = await setupLayout({
      "agent/permissions.json": { mode: "yolo" },
      "project/.pi/permissions.json": { mode: "yolo" },
    });

    const result = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);

    expect(result.merged.mode).toBe("manual");
    expect(result.issues).toEqual([
      expect.stringContaining(`'${path.join(agentDir, "permissions.json")}'`),
      expect.stringContaining(`'${path.join(projectDir, ".pi", "permissions.json")}'`),
    ]);
    expect(result.issues.every((issue) => issue.includes("sentinel.json"))).toBe(true);
  });

  it("does not warn when sentinel.json exists beside permissions.json", async () => {
    const { agentDir, projectDir, extensionRoot } = await setupLayout({
      "agent/permissions.json": { mode: "yolo" },
      "agent/sentinel.json": { mode: "auto" },
    });

    const result = loadAndMergeConfigs(agentDir, projectDir, extensionRoot);

    expect(result.issues).toEqual([]);
    expect(result.merged.mode).toBe("auto");
  });
});
