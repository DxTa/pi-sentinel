import { describe, expect, it } from "vitest";

import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { lockCommand, SHORT_LOCK_TIMEOUT_MS, withFileLock } from "./auto-mode-file-lock.js";

describe("lockCommand", () => {
  it("uses an absolute flock executable on Linux", () => {
    expect(lockCommand("/tmp/pi-sentinel.lock", "linux").command).toBe("/usr/bin/flock");
  });
});

describe("lockCommand runtime", () => {
  it("runs the lock holder with the given runtime, not the host binary", () => {
    const { args } = lockCommand("/tmp/pi-sentinel.lock", "linux", "/usr/bin/node");
    expect(args.slice(0, 4)).toEqual(["-x", "/tmp/pi-sentinel.lock", "/usr/bin/node", "-e"]);
  });
});

describe("withFileLock timeout", () => {
  // The holder keeps the lock for holdSeconds, then exits.
  async function withHeldLock(holdSeconds: number, test: (lockPath: string) => Promise<void>) {
    const dir = await mkdtemp(join(tmpdir(), "pi-sentinel-lock-"));
    const lockPath = join(dir, "held.lock");
    const holder = spawn("/usr/bin/flock", ["-x", lockPath, "/bin/sleep", String(holdSeconds)], { detached: true });
    try {
      await new Promise((resolve) => setTimeout(resolve, 200));
      await test(lockPath);
    } finally {
      try { process.kill(-holder.pid!, "SIGKILL"); } catch { /* already exited */ }
      await rm(dir, { recursive: true, force: true });
    }
  }

  it("rejects within the timeout when another process holds the lock", async () => {
    await withHeldLock(30, async (lockPath) => {
      const started = Date.now();
      await expect(withFileLock(lockPath, async () => "ran", SHORT_LOCK_TIMEOUT_MS)).rejects.toThrow("Timed out");
      expect(Date.now() - started).toBeLessThan(SHORT_LOCK_TIMEOUT_MS + 2000);
    });
  });

  it("waits for the holder when no timeout is given", async () => {
    await withHeldLock(3, async (lockPath) => {
      const started = Date.now();
      await expect(withFileLock(lockPath, async () => "ran")).resolves.toBe("ran");
      expect(Date.now() - started).toBeGreaterThan(SHORT_LOCK_TIMEOUT_MS);
    });
  }, 15_000);
});
