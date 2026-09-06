import { homedir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { normalizeSandboxConfig, validateSandboxBindPath, validateSandboxUnmaskPath } from "./settings.js";

describe("normalizeSandboxConfig", () => {
  it("defaults to enabled SRT with online network profile", () => {
    const config = normalizeSandboxConfig(undefined);

    expect(config).toMatchObject({
      enabled: true,
      backend: "srt",
      defaultProfile: "online-dev",
    });
    expect(config.profiles["online-dev"]?.network).toBe(true);
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

  it("accepts legacy bwrap backend selector", () => {
    expect(normalizeSandboxConfig({ enabled: true, backend: "bwrap" }).backend).toBe("bwrap");
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

  it("allows read-only unmasking under credential directories but not generic binds", () => {
    const keyPath = path.join(homedir(), ".ssh", "id_test");

    expect(() => validateSandboxUnmaskPath(keyPath)).not.toThrow();
    expect(() => validateSandboxBindPath(keyPath)).toThrow(/sensitive/);
  });
});
