import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { AUTO_MODE_BUILD_ID } from "./auto-mode-build";
import { AutoModeClient, createUnixSocketWorkerTransport } from "./auto-mode-client";
import { parseAutoModeWorkerArgs, startWorker } from "./auto-mode-worker-main";

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

vi.mock("./auto-mode-model.ts", () => ({
  loadInferenceRuntime: async () => ({}),
  // A model download that outlasts the client's startup window.
  ensureModelAssets: () => new Promise<void>(() => {}),
  createClassifier: async () => {
    throw new Error("createClassifier must not run before the download finishes");
  },
}));

describe("startWorker", () => {
  it("fails requests fast while the model is still downloading", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pi-worker-main-"));
    const socketPath = join(dir, "worker.sock");
    const server = await startWorker(["--socket", socketPath, "--model-dir", join(dir, "models")]);
    try {
      const client = new AutoModeClient(createUnixSocketWorkerTransport(socketPath), {
        expectedBuildId: AUTO_MODE_BUILD_ID,
      });
      const startedAt = Date.now();
      const result = await client.evaluate("hello");
      expect(result.status).toBe("unavailable");
      expect(Date.now() - startedAt).toBeLessThan(5_000);
    } finally {
      await server.close();
    }
  }, 15_000);
});
