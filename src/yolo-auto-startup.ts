import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdir, open } from "node:fs/promises";
import * as net from "node:net";
import { join } from "node:path";

import { YoloAutoBuildMismatchError } from "./yolo-auto-client";

const SOCKET_PROBE_TIMEOUT_MS = 250;

export function isUnixSocketActive(socketPath: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection(socketPath);
    let settled = false;
    const finish = (active: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(active);
    };
    socket.setTimeout(SOCKET_PROBE_TIMEOUT_MS, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED" || error.code === "ENOENT") {
        finish(false);
        return;
      }
      finish(false);
    });
  });
}


export async function waitForWorkerStartup(
  waitUntilReady: () => Promise<unknown>,
  replaceWorker: () => Promise<void>,
): Promise<void> {
  try {
    await waitUntilReady();
  } catch (error) {
    if (!(error instanceof YoloAutoBuildMismatchError)) throw error;
    await replaceWorker();
    await waitUntilReady();
  }
}


export interface DetachedYoloAutoWorker {
  process: ChildProcess;
  startupSignal: Promise<void>;
}

export async function spawnDetachedYoloAutoWorker(
  agentDir: string,
  executable: string,
  args: readonly string[],
): Promise<DetachedYoloAutoWorker> {
  const logDir = join(agentDir, "runtime", "pi-sentinel");
  const logPath = join(logDir, "worker.log");
  await mkdir(logDir, { recursive: true, mode: 0o700 });
  await chmod(logDir, 0o700);
  const logFile = await open(logPath, "a", 0o600);

  let child: ChildProcess;
  try {
    await chmod(logPath, 0o600);
    child = spawn(executable, [...args], {
      cwd: agentDir,
      detached: true,
      stdio: ["ignore", logFile.fd, logFile.fd],
    });
  } catch (error) {
    await logFile.close();
    throw error;
  }

  const startupSignal = once(child, "spawn")
    .then(() => undefined)
    .finally(() => logFile.close());
  void startupSignal.catch(() => undefined);
  child.unref();
  return { process: child, startupSignal };
}
