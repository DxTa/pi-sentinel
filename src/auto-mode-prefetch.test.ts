import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SCRIPT = join(import.meta.dirname, "..", "bin", "prefetch-model.mjs");

function runPrefetch(env: Record<string, string>) {
  return spawnSync(process.execPath, ["--experimental-strip-types", SCRIPT], {
    env: { PATH: process.env.PATH ?? "", ...env },
    encoding: "utf8",
  });
}

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "pi-sentinel-prefetch-"));
}

describe("bin/prefetch-model.mjs", () => {
  it("does nothing when PI_SENTINEL_SKIP_MODEL_DOWNLOAD=1", () => {
    const modelDir = join(tempDir(), "models");
    const result = runPrefetch({ PI_SENTINEL_SKIP_MODEL_DOWNLOAD: "1", PI_SENTINEL_AUTO_MODEL_DIR: modelDir });
    expect(result.status).toBe(0);
    expect(existsSync(modelDir)).toBe(false);
  });

  it("does nothing under CI", () => {
    const modelDir = join(tempDir(), "models");
    const result = runPrefetch({ CI: "1", PI_SENTINEL_AUTO_MODEL_DIR: modelDir });
    expect(result.status).toBe(0);
    expect(existsSync(modelDir)).toBe(false);
  });

  it("warns and exits 0 when the model directory cannot be created", () => {
    const blocker = join(tempDir(), "file");
    writeFileSync(blocker, "");
    const result = runPrefetch({ PI_SENTINEL_AUTO_MODEL_DIR: join(blocker, "models") });
    expect(result.status).toBe(0);
    expect(result.stderr).toContain("auto-mode model prefetch skipped");
  });
});
