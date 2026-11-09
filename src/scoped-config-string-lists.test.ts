import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  listHostFallbackCommands,
  listSandboxPaths,
  listYoloAskPatterns,
  persistSandboxPathGrantToConfig,
  removeSandboxPathGrantFromConfig,
  setHostFallbackCommand,
  setYoloAskPattern,
} from "./scoped-config";

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeWorkspace(): Promise<{ cwd: string; configPath: string }> {
  const cwd = await mkdtemp(path.join(tmpdir(), "pi-scoped-strings-"));
  tempPaths.push(cwd);
  const configPath = path.join(cwd, ".pi", "sentinel.json");
  await mkdir(path.dirname(configPath), { recursive: true });
  return { cwd, configPath };
}

describe("sandbox path grants in one scope file", () => {
  it("lists read-only and writable paths, then removes one", async () => {
    const { cwd, configPath } = await makeWorkspace();
    const cache = path.join(cwd, "cache");
    const out = path.join(cwd, "out");
    await mkdir(cache);
    await mkdir(out);

    persistSandboxPathGrantToConfig(configPath, cache, "ro", cwd);
    persistSandboxPathGrantToConfig(configPath, out, "rw", cwd);
    expect(listSandboxPaths(configPath, cwd)).toEqual({ ro: [cache], rw: [out] });

    removeSandboxPathGrantFromConfig(configPath, cache, cwd);
    expect(listSandboxPaths(configPath, cwd)).toEqual({ ro: [], rw: [out] });
  });
});

describe("host fallback commands in one scope file", () => {
  it("adds once, lists, and removes a command prefix", async () => {
    const { cwd, configPath } = await makeWorkspace();

    setHostFallbackCommand(configPath, "docker compose", true, cwd);
    setHostFallbackCommand(configPath, "docker compose", true, cwd);
    expect(listHostFallbackCommands(configPath, cwd)).toEqual(["docker compose"]);

    setHostFallbackCommand(configPath, "docker compose", false, cwd);
    expect(listHostFallbackCommands(configPath, cwd)).toEqual([]);
  });
});

describe("yolo ask patterns in one scope file", () => {
  it("adds once, lists, and removes a pattern", async () => {
    const { cwd, configPath } = await makeWorkspace();

    setYoloAskPattern(configPath, "rm -rf *", true, cwd);
    setYoloAskPattern(configPath, "rm -rf *", true, cwd);
    expect(listYoloAskPatterns(configPath, cwd)).toEqual(["rm -rf *"]);

    setYoloAskPattern(configPath, "rm -rf *", false, cwd);
    expect(listYoloAskPatterns(configPath, cwd)).toEqual([]);
  });
});
