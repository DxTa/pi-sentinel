import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { resolveBwrapRunnerPath } from "./settings.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
const originalRunner = process.env.PI_BWRAP_RUNNER;

afterEach(() => {
  if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
  if (originalRunner === undefined) delete process.env.PI_BWRAP_RUNNER;
  else process.env.PI_BWRAP_RUNNER = originalRunner;
});

describe("standalone package paths", () => {
  it("resolves bundled bwrap runner from package location", () => {
    process.env.PI_CODING_AGENT_DIR = "/tmp/unrelated-pi-agent";
    delete process.env.PI_BWRAP_RUNNER;

    const runnerPath = resolveBwrapRunnerPath(null);

    expect(runnerPath).toBe(resolve(packageRoot, "bin/bwrap-run.sh"));
    expect(existsSync(runnerPath)).toBe(true);
  });
});
