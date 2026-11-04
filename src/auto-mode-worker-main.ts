import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ensureModelAssets, createClassifier, loadInferenceRuntime } from "./auto-mode-model.ts";
import { AUTO_MODE_BUILD_ID } from "./auto-mode-build.ts";
import { AutoModeWorkerServer } from "./auto-mode-worker.ts";

export function parseAutoModeWorkerArgs(argv: readonly string[]) {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      socket: { type: "string" },
      "model-dir": { type: "string" },
    },
    allowPositionals: false,
  });
  if (!values.socket || !values["model-dir"]) {
    throw new Error("Both --socket and --model-dir are required.");
  }
  return {
    socketPath: resolve(values.socket),
    modelDir: resolve(values["model-dir"]),
  };
}

async function startWorker(argv: readonly string[]): Promise<void> {
  const { socketPath, modelDir } = parseAutoModeWorkerArgs(argv);
  // Fail before the ~320 MB model download when the runtime cannot load here.
  await loadInferenceRuntime();
  await ensureModelAssets({ dir: modelDir });
  const classifier = await createClassifier(modelDir);
  const server = new AutoModeWorkerServer({
    socketPath,
    buildId: AUTO_MODE_BUILD_ID,
    provider: {
      ready: async () => {},
      classify: (text) => classifier.classify(text),
      close: () => classifier.close(),
    },
  });
  try {
    await server.start();
  } catch (error) {
    await server.close();
    throw error;
  }
}

const scriptPath = process.argv[1];
if (scriptPath && fileURLToPath(import.meta.url) === resolve(scriptPath)) {
  void startWorker(process.argv.slice(2)).catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  });
}
