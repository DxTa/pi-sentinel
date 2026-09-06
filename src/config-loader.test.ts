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

describe("yoloAskBashPatterns config", () => {
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
        yoloMode: false,
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
        yoloMode: true,
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
        yoloMode: false,
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
      yoloMode: false,
      permission: {
        bash: {
          "git *": "ask",
          "git push *": "deny",
        },
      },
    });
  });
});
