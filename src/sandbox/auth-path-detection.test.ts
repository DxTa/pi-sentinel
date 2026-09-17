import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { detectImplicitAuthAccess } from "./auth-path-detection.js";

describe("detectImplicitAuthAccess", () => {
  it("detects Docker config as implicit auth for direct Docker commands", async () => {
    const configPath = resolve(homedir(), ".docker/config.json");
    if (!existsSync(configPath)) return;

    await expect(detectImplicitAuthAccess("docker version", null)).resolves.toEqual({
      kind: "docker-auth",
      candidatePaths: [configPath],
      needsSocketFallback: false,
    });
  });

  it("does not infer Docker auth for compound commands", async () => {
    await expect(detectImplicitAuthAccess("docker version && cat README.md", null)).resolves.toBeNull();
  });
});
