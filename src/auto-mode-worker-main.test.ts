import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseAutoModeWorkerArgs } from "./auto-mode-worker-main";

describe("parseAutoModeWorkerArgs", () => {
  it("requires and resolves socket and model directory flags", () => {
    expect(parseAutoModeWorkerArgs([
      "--socket", "./run/worker.sock",
      "--model-dir", "./models/lion-warden",
    ])).toEqual({
      socketPath: resolve("./run/worker.sock"),
      modelDir: resolve("./models/lion-warden"),
    });
  });

  it("rejects missing required arguments", () => {
    expect(() => parseAutoModeWorkerArgs(["--socket", "worker.sock"]))
      .toThrow(/--model-dir/);
  });

  it("runs directly under Node's TypeScript stripping mode", () => {
    const entry = fileURLToPath(new URL("./auto-mode-worker-main.ts", import.meta.url));
    const result = spawnSync(process.execPath, [entry], { encoding: "utf8" });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Both --socket and --model-dir are required.");
    expect(result.stderr).not.toContain("ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX");
  });

  it("rejects unknown options and positional arguments", () => {
    expect(() => parseAutoModeWorkerArgs([
      "--socket", "worker.sock",
      "--model-dir", "models",
      "--unexpected",
    ])).toThrow();
    expect(() => parseAutoModeWorkerArgs([
      "--socket", "worker.sock",
      "--model-dir", "models",
      "extra",
    ])).toThrow();
  });
});
