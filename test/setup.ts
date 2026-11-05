// Tests must never start the real classifier worker: a detached worker outlives the test,
// downloads the ~130 MB model into the test's temp agent dir, and fills TMPDIR.
// A test that needs a worker serves PI_SENTINEL_AUTO_SOCKET itself (see index-srt-default-smoke.test.ts).
import { tmpdir } from "node:os";
import { vi } from "vitest";

// Temp dirs may live inside this repo (TMPDIR=./tmp). Stop git's repo search at TMPDIR, so a test's
// temp project is not merged with the outer repo and its sibling temp dirs.
process.env.GIT_CEILING_DIRECTORIES = tmpdir();

vi.mock("../src/auto-mode-startup.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/auto-mode-startup.ts")>();
  return {
    ...actual,
    spawnDetachedAutoModeWorker: async (agentDir: string, executable: string, args: readonly string[]) => {
      if (args.some((arg) => arg.endsWith("auto-mode-worker-main.ts"))) {
        throw new Error("Tests may not spawn the classifier worker; serve PI_SENTINEL_AUTO_SOCKET instead.");
      }
      return actual.spawnDetachedAutoModeWorker(agentDir, executable, args);
    },
  };
});
