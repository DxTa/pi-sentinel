import { homedir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { normalizeSandboxConfig, validateSandboxBindPath } from "./settings.js";

describe("normalizeSandboxConfig", () => {
  it("reads host fallback command prefixes without duplicates", () => {
    expect(normalizeSandboxConfig(undefined).hostFallbackCommands).toEqual([]);
    expect(normalizeSandboxConfig({ hostFallbackCommands: ["docker build", "docker build"] }).hostFallbackCommands)
      .toEqual(["docker build"]);
  });

  it("defaults to enabled SRT with online network profile", () => {
    const config = normalizeSandboxConfig(undefined);

    expect(config).toMatchObject({
      enabled: true,
      backend: "srt",
      defaultProfile: "online-dev",
    });
    expect(config.profiles["online-dev"]?.network).toBe(true);
    expect(config.profiles["online-dev"]?.allowDocker).toBe(true);
    expect(config.profiles["offline-dev"]?.allowDocker).toBe(true);
    expect(config.bypassCommands).toEqual(["*"]);
  });

  it("defaults custom profiles to Docker access unless explicitly disabled", () => {
    const config = normalizeSandboxConfig({
      profiles: {
        "custom-dev": { network: false },
        "no-docker": { network: false, allowDocker: false },
      },
    });

    expect(config.profiles["custom-dev"]?.allowDocker).toBe(true);
    expect(config.profiles["no-docker"]?.allowDocker).toBe(false);
  });

  it("keeps sandbox enabled for partial configs", () => {
    expect(normalizeSandboxConfig({ defaultProfile: "offline-dev" })).toMatchObject({
      enabled: true,
      defaultProfile: "offline-dev",
    });
  });

  it("preserves an explicit sandbox disable", () => {
    expect(normalizeSandboxConfig({ enabled: false }).enabled).toBe(false);
  });

  it("defaults backend to srt", () => {
    expect(normalizeSandboxConfig({ enabled: true }).backend).toBe("srt");
  });

  it("rejects removed bwrap backend selector", () => {
    expect(() => normalizeSandboxConfig({ enabled: true, backend: "bwrap" })).toThrow(
      "Invalid sandbox.backend; only 'srt' is supported.",
    );
  });

  it.each([
    ["enabled", { enabled: "yes" }],
    ["network", { network: "yes" }],
  ])("rejects invalid sandbox.%s", (_key, config) => {
    expect(() => normalizeSandboxConfig(config)).toThrow(/expected boolean/);
  });

  it("rejects inherited profile names", () => {
    expect(() => normalizeSandboxConfig({ defaultProfile: "constructor" })).toThrow(/defaultProfile/);
  });

  it("rejects credential directories as sandbox binds", () => {
    const keyPath = path.join(homedir(), ".ssh", "id_test");

    expect(() => validateSandboxBindPath(keyPath)).toThrow(/sensitive/);
  });
});
