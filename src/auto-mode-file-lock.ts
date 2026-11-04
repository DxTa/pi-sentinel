import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { open } from "node:fs/promises";

import { helperRuntimePath } from "./host-runtime.ts";

/** For short critical sections; a waiter gives up instead of hanging behind a stuck holder. */
export const SHORT_LOCK_TIMEOUT_MS = 2000;
const LOCK_HOLDER_SCRIPT = 'process.stdout.write("locked\\n"); process.stdin.resume();';

export function lockCommand(
  lockPath: string,
  platform: NodeJS.Platform = process.platform,
  runtime: string = helperRuntimePath(),
): { command: string; args: string[] } {
  const holderCommand = [runtime, "-e", LOCK_HOLDER_SCRIPT];
  if (platform === "darwin") {
    return { command: "/usr/bin/lockf", args: ["-k", lockPath, ...holderCommand] };
  }
  if (platform === "linux") {
    return { command: "/usr/bin/flock", args: ["-x", lockPath, ...holderCommand] };
  }
  throw new Error("Advisory file locking is unsupported on this platform.");
}

async function acquireFileLock(lockPath: string, timeoutMs: number | undefined): Promise<ChildProcess> {
  const file = await open(lockPath, "a", 0o600);
  try {
    await file.chmod(0o600);
  } finally {
    await file.close();
  }

  const { command, args } = lockCommand(lockPath);
  const lockProcess = spawn(command, args, { stdio: ["pipe", "pipe", "ignore"] });
  if (!lockProcess.stdin || !lockProcess.stdout) {
    lockProcess.kill();
    throw new Error("Unable to start advisory file lock process.");
  }
  await new Promise<void>((resolve, reject) => {
    let acquired = false;
    const timer = timeoutMs === undefined
      ? undefined
      : setTimeout(() => reject(new Error("Timed out acquiring advisory file lock.")), timeoutMs);
    lockProcess.once("error", () => {
      clearTimeout(timer);
      if (!acquired) reject(new Error("Unable to acquire advisory file lock."));
    });
    lockProcess.once("close", () => {
      clearTimeout(timer);
      if (!acquired) reject(new Error("Unable to acquire advisory file lock."));
    });
    lockProcess.stdout.once("data", () => {
      acquired = true;
      clearTimeout(timer);
      resolve();
    });
  }).catch((error) => {
    lockProcess.stdin?.end();
    lockProcess.kill();
    throw error;
  });
  return lockProcess;
}

/** Without timeoutMs the caller waits as long as the holder runs (the model download holds its lock for minutes). */
export async function withFileLock<T>(lockPath: string, run: () => Promise<T>, timeoutMs?: number): Promise<T> {
  const lockProcess = await acquireFileLock(lockPath, timeoutMs);
  try {
    return await run();
  } finally {
    const closed = once(lockProcess, "close");
    lockProcess.stdin?.end();
    await closed;
  }
}
