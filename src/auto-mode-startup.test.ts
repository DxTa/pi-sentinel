import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { once } from "node:events";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createUnixSocketWorkerTransport,
  AutoModeBuildMismatchError,
  AUTO_MODE_PROTOCOL_VERSION,
  AutoModeClient,
} from "./auto-mode-client";
import { isUnixSocketActive, spawnDetachedAutoModeWorker, waitForWorkerStartup } from "./auto-mode-startup";

const roots: string[] = [];
const TEST_BUILD_ID = "pi-sentinel-test:model-r1";

function encodeFrame(value: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

async function startHandshakeServer(
  socketPath: string,
  response: Record<string, unknown>,
  onHandshake: (request: unknown) => void = () => undefined,
  listenDelayMs = 0,
): Promise<net.Server> {
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4) return;
      const frameLength = buffer.readUInt32BE(0);
      if (buffer.length < frameLength + 4) return;
      onHandshake(JSON.parse(buffer.subarray(4, frameLength + 4).toString("utf8")));
      socket.write(encodeFrame(response));
    });
  });
  if (listenDelayMs > 0) {
    await new Promise<void>((resolve) => setTimeout(resolve, listenDelayMs));
  }
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  return server;
}

function readyHandshake(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "handshake",
    protocolVersion: AUTO_MODE_PROTOCOL_VERSION,
    status: "ready",
    buildId: TEST_BUILD_ID,
    ...overrides,
  };
}

function createClient(socketPath: string): AutoModeClient {
  return new AutoModeClient(createUnixSocketWorkerTransport(socketPath), {
    expectedBuildId: TEST_BUILD_ID,
  });
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("isUnixSocketActive", () => {
  it("distinguishes missing, stale, and active Unix sockets", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-startup-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");

    await expect(isUnixSocketActive(socketPath)).resolves.toBe(false);

    const staleServer = net.createServer();
    await new Promise<void>((resolve) => staleServer.listen(socketPath, resolve));
    await new Promise<void>((resolve) => staleServer.close(() => resolve()));
    await expect(isUnixSocketActive(socketPath)).resolves.toBe(false);

    const activeServer = net.createServer();
    await new Promise<void>((resolve) => activeServer.listen(socketPath, resolve));
    await expect(isUnixSocketActive(socketPath)).resolves.toBe(true);
    await new Promise<void>((resolve) => activeServer.close(() => resolve()));
  });
});

describe("spawnDetachedAutoModeWorker", () => {
  it("logs detached worker output in an owner-only file", async () => {
    const agentDir = await mkdtemp(join(tmpdir(), "pi-yolo-worker-log-"));
    roots.push(agentDir);
    const worker = await spawnDetachedAutoModeWorker(
      agentDir,
      process.execPath,
      ["-e", "console.log(\"worker stdout\"); console.error(\"worker stderr\")"],
    );
    await worker.startupSignal;
    if (worker.process.exitCode === null) await once(worker.process, "exit");

    const logDir = join(agentDir, "runtime", "pi-sentinel");
    const log = await readFile(join(logDir, "worker.log"), "utf8");
    expect(log).toContain("worker stdout");
    expect(log).toContain("worker stderr");
    expect((await stat(logDir)).mode & 0o777).toBe(0o700);
    expect((await stat(join(logDir, "worker.log"))).mode & 0o777).toBe(0o600);
  });
});

describe("waitForWorkerStartup", () => {
  it("starts one replacement and retries readiness after a build mismatch", async () => {
    let attempts = 0;
    const waitUntilReady = async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new AutoModeBuildMismatchError("old-build", "new-build");
      }
      return "new-build";
    };
    let replacements = 0;
    const replaceWorker = async () => { replacements += 1; };

    await expect(waitForWorkerStartup(waitUntilReady, replaceWorker)).resolves.toBeUndefined();

    expect(replacements).toBe(1);
    expect(attempts).toBe(2);
  });

  it("does not replace the worker for ordinary readiness failures", async () => {
    const error = new Error("worker unavailable");
    let replacements = 0;
    const replaceWorker = async () => { replacements += 1; };

    await expect(waitForWorkerStartup(async () => { throw error; }, replaceWorker)).rejects.toBe(error);
    expect(replacements).toBe(0);
  });
});

describe("AutoMode worker readiness", () => {
  it("confirms a shared endpoint with protocol handshakes only", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-readiness-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");
    const requests: unknown[] = [];
    const server = await startHandshakeServer(
      socketPath,
      readyHandshake(),
      (request) => requests.push(request),
    );
    const clients = [createClient(socketPath), createClient(socketPath)];

    try {
      await Promise.all(clients.map((client) => client.waitUntilReady()));
      expect(requests).toHaveLength(2);
      expect(requests).toEqual([
        expect.objectContaining({ type: "handshake", protocolVersion: AUTO_MODE_PROTOCOL_VERSION }),
        expect.objectContaining({ type: "handshake", protocolVersion: AUTO_MODE_PROTOCOL_VERSION }),
      ]);
    } finally {
      clients.forEach((client) => client.close());
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("retries readiness when the shared socket appears after initial refusal", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-readiness-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");
    const serverPromise = startHandshakeServer(socketPath, readyHandshake(), undefined, 75);
    const client = createClient(socketPath);
    const ready = client.waitUntilReady().then(() => true, () => false);
    const server = await serverPromise;

    try {
      await expect(ready).resolves.toBe(true);
    } finally {
      client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("rejects readiness when the endpoint is unavailable", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-readiness-"));
    roots.push(root);
    const client = createClient(join(root, "worker.sock"));
    const ready = client.waitUntilReady();
    client.close();
    await expect(ready).rejects.toThrow();
  });

  it.each([
    ["failed status", readyHandshake({ status: "failed" })],
    ["invalid build ID", readyHandshake({ buildId: "" })],
    ["protocol mismatch", readyHandshake({ protocolVersion: AUTO_MODE_PROTOCOL_VERSION + 1 })],
  ])("rejects endpoint with %s", async (_reason, response) => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-readiness-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");
    const server = await startHandshakeServer(socketPath, response);
    const client = createClient(socketPath);

    try {
      await expect(client.waitUntilReady()).rejects.toThrow();
    } finally {
      client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("cancels an in-progress readiness connection when closed", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-readiness-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");
    const server = await startHandshakeServer(socketPath, readyHandshake());
    let connectionCount = 0;
    server.on("connection", () => connectionCount++);
    const client = createClient(socketPath);
    const pending = client.waitUntilReady();
    client.close();

    try {
      await expect(pending).rejects.toThrow();
      expect(connectionCount).toBe(0);
    } finally {
      client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("keeps concurrent readiness callers behind the pending handshake", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-readiness-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");
    let serverSocket: net.Socket | undefined;
    let resolveHandshake!: () => void;
    const handshakeReceived = new Promise<void>((resolve) => {
      resolveHandshake = resolve;
    });
    const server = net.createServer((socket) => {
      serverSocket = socket;
      let buffer = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length < 4) return;
        const frameLength = buffer.readUInt32BE(0);
        if (buffer.length < frameLength + 4) return;
        resolveHandshake();
      });
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    const client = createClient(socketPath);
    const first = client.waitUntilReady();
    await handshakeReceived;
    const second = client.waitUntilReady();

    try {
      const secondSettled = await Promise.race([
        second.then(() => true, () => true),
        new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 50)),
      ]);
      expect(secondSettled).toBe(false);
    } finally {
      serverSocket?.write(encodeFrame(readyHandshake()));
      await Promise.allSettled([first, second]);
      client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
