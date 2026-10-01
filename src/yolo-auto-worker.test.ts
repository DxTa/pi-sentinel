import { mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { once } from "node:events";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { YoloAutoHeads } from "./yolo-auto-policy";
import { withFileLock } from "./yolo-auto-file-lock";
import { YoloAutoWorkerServer, type WorkerProvider } from "./yolo-auto-worker";

const tempRoots: string[] = [];
const PROTOCOL_VERSION = 2;
const heads: YoloAutoHeads = {
  injection: { injection: 0.01 },
  threat: { benign: 0.99 },
  tool_class: { files: 1 },
  tool_action: { read: 1 },
  tool_tags: { "source:sensitive": 0, "source:untrusted": 0, "sink:external": 0 },
  sensitive_document: { none: 1 },
  routing: { local: 1 },
};

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function provider(overrides: Partial<WorkerProvider> = {}): WorkerProvider {
  return {
    ready: async () => undefined,
    classify: async () => heads,
    ...overrides,
  };
}

function encodeFrame(value: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

function writeFrame(socket: net.Socket, value: unknown): void {
  socket.write(encodeFrame(value));
}

function readFrame(socket: net.Socket): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const cleanup = () => {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("Worker closed before returning a frame."));
    };
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4) return;
      const length = buffer.readUInt32BE(0);
      if (buffer.length < length + 4) return;
      cleanup();
      try {
        resolve(JSON.parse(buffer.subarray(4, length + 4).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

async function connectWorker(socketPath: string) {
  const socket = net.createConnection(socketPath);
  await once(socket, "connect");
  const handshakeResponse = readFrame(socket);
  writeFrame(socket, { type: "handshake", protocolVersion: PROTOCOL_VERSION });
  const handshake = await handshakeResponse;
  return {
    socket,
    handshake,
    request(request: unknown): Promise<unknown> {
      const response = readFrame(socket);
      writeFrame(socket, request);
      return response;
    },
    close(): void {
      socket.destroy();
    },
  };
}

function classifyRequest(requestId: string, text: string, deadlineMs = 2_000) {
  return { type: "classify", protocolVersion: PROTOCOL_VERSION, requestId, deadlineMs, text };
}

describe("YoloAutoWorkerServer", () => {
  it("waits for classifier readiness and returns the worker build ID", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let releaseReady!: () => void;
    let signalReadyStarted!: () => void;
    const readyStarted = new Promise<void>((resolve) => { signalReadyStarted = resolve; });
    const readyGate = new Promise<void>((resolve) => { releaseReady = resolve; });
    let readyCalls = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider({
        ready: async () => {
          readyCalls++;
          signalReadyStarted();
          await readyGate;
        },
      }),
    });
    const starting = server.start();
    await readyStarted;
    expect(existsSync(socketPath)).toBe(false);
    releaseReady();
    await starting;

    const client = await connectWorker(socketPath);
    expect(client.handshake).toEqual({
      type: "handshake",
      protocolVersion: PROTOCOL_VERSION,
      status: "ready",
      buildId: "test-build-id",
    });
    expect(readyCalls).toBe(1);

    client.close();
    await server.close();
  });

  it("classifies text and returns all model heads", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    const inputs: string[] = [];
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider({ classify: async (text) => { inputs.push(text); return heads; } }),
    });
    await server.start();
    const client = await connectWorker(socketPath);

    await expect(client.request(classifyRequest("read-1", "tool=read path=notes.txt"))).resolves.toEqual({
      type: "classify",
      protocolVersion: PROTOCOL_VERSION,
      requestId: "read-1",
      status: "complete",
      heads,
    });
    expect(inputs).toEqual(["tool=read path=notes.txt"]);

    client.close();
    await server.close();
  });

  it("fails closed when the request queue is full", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let signalEvaluationStarted!: () => void;
    let releaseEvaluation!: () => void;
    const evaluationStarted = new Promise<void>((resolve) => { signalEvaluationStarted = resolve; });
    const evaluationGate = new Promise<void>((resolve) => { releaseEvaluation = resolve; });
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      queueLimit: 1,
      provider: provider({
        classify: async () => {
          signalEvaluationStarted();
          await evaluationGate;
          return heads;
        },
      }),
    });
    await server.start();
    const firstClient = await connectWorker(socketPath);
    const first = firstClient.request(classifyRequest("first", "first"));
    await evaluationStarted;
    const queuedClient = await connectWorker(socketPath);
    const queued = queuedClient.request(classifyRequest("queued", "queued"));
    const overflowClient = await connectWorker(socketPath);

    await expect(overflowClient.request(classifyRequest("overflow", "overflow"))).resolves.toMatchObject({
      requestId: "overflow",
      status: "failed",
      error: "queue_overflow",
    });
    releaseEvaluation();
    await expect(first).resolves.toMatchObject({ requestId: "first", status: "complete" });
    await expect(queued).resolves.toMatchObject({ requestId: "queued", status: "complete" });

    firstClient.close();
    queuedClient.close();
    overflowClient.close();
    await server.close();
  });

  it("keeps timed-out classification serialized and defers provider cleanup", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let signalClassificationStarted!: () => void;
    let releaseClassification!: () => void;
    const classificationStarted = new Promise<void>((resolve) => { signalClassificationStarted = resolve; });
    const classificationGate = new Promise<void>((resolve) => { releaseClassification = resolve; });
    const inputs: string[] = [];
    let providerCloses = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider({
        classify: async (text) => {
          inputs.push(text);
          if (text === "first") {
            signalClassificationStarted();
            await classificationGate;
          }
          return heads;
        },
        close: () => { providerCloses++; },
      }),
    });
    await server.start();
    const firstClient = await connectWorker(socketPath);
    const secondClient = await connectWorker(socketPath);
    let closing: Promise<void> | undefined;

    try {
      const first = firstClient.request(classifyRequest("first", "first", 100));
      await classificationStarted;
      const second = secondClient.request(classifyRequest("second", "second"))
        .then((response) => ({ response }), (error) => ({ error }));

      await expect(first).resolves.toEqual({
        type: "classify",
        protocolVersion: PROTOCOL_VERSION,
        requestId: "first",
        status: "failed",
        error: "deadline_exceeded",
      });
      expect(inputs).toEqual(["first"]);

      const firstClientClosed = once(firstClient.socket, "close");
      firstClient.socket.end(encodeFrame({ type: "shutdown", protocolVersion: PROTOCOL_VERSION }));
      await firstClientClosed;
      closing = server.close();
      expect(providerCloses).toBe(0);

      releaseClassification();
      await closing;
      expect(providerCloses).toBe(1);
      expect(inputs).toEqual(["first"]);
      expect(await second).toHaveProperty("error");
    } finally {
      releaseClassification();
      firstClient.close();
      secondClient.close();
      await (closing ?? server.close());
    }
  });

  it("rejects a synchronous classifier result that returns after its deadline", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider({
        classify: async () => {
          const finishAt = Date.now() + 40;
          while (Date.now() < finishAt) { /* Simulate synchronous preprocessing. */ }
          return heads;
        },
      }),
    });
    await server.start();
    const client = await connectWorker(socketPath);

    try {
      await expect(client.request(classifyRequest("slow", "slow", 1))).resolves.toMatchObject({
        requestId: "slow",
        status: "failed",
        error: "deadline_exceeded",
      });
    } finally {
      client.close();
      await server.close();
    }
  });

  it("rejects a queued classification whose deadline expires before execution", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let signalClassificationStarted!: () => void;
    let releaseClassification!: () => void;
    const classificationStarted = new Promise<void>((resolve) => { signalClassificationStarted = resolve; });
    const classificationGate = new Promise<void>((resolve) => { releaseClassification = resolve; });
    const inputs: string[] = [];
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider({
        classify: async (text) => {
          inputs.push(text);
          if (text === "first") {
            signalClassificationStarted();
            await classificationGate;
          }
          return heads;
        },
      }),
    });
    await server.start();
    const firstClient = await connectWorker(socketPath);
    const secondClient = await connectWorker(socketPath);

    try {
      const first = firstClient.request(classifyRequest("first", "first", 1_000));
      await classificationStarted;
      const expired = secondClient.request(classifyRequest("expired", "expired", 10));
      await new Promise<void>((resolve) => setTimeout(resolve, 30));
      releaseClassification();

      await expect(first).resolves.toMatchObject({ requestId: "first", status: "complete" });
      await expect(expired).resolves.toMatchObject({
        requestId: "expired",
        status: "failed",
        error: "deadline_exceeded",
      });
      expect(inputs).toEqual(["first"]);
    } finally {
      releaseClassification();
      firstClient.close();
      secondClient.close();
      await server.close();
    }
  });

  it("shuts down on an explicit shutdown request", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let providerCloses = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider({ close: () => { providerCloses++; } }),
    });
    await server.start();
    const client = await connectWorker(socketPath);
    const clientClosed = once(client.socket, "close");

    client.socket.end(encodeFrame({ type: "shutdown", protocolVersion: PROTOCOL_VERSION }));
    await clientClosed;
    await server.close();

    expect(providerCloses).toBe(1);
    expect(existsSync(socketPath)).toBe(false);
  });

  it("waits for the socket lock before binding", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    const lockPath = join(root, "worker.sock.lock");
    const staleServer = net.createServer();
    await new Promise<void>((resolve) => staleServer.listen(socketPath, resolve));
    await new Promise<void>((resolve) => staleServer.close(() => resolve()));

    let releaseLock!: () => void;
    let signalLockAcquired!: () => void;
    const lockAcquired = new Promise<void>((resolve) => { signalLockAcquired = resolve; });
    const heldLock = withFileLock(lockPath, async () => {
      await new Promise<void>((resolve) => {
        releaseLock = resolve;
        signalLockAcquired();
      });
    });
    await lockAcquired;

    const server = new YoloAutoWorkerServer({ socketPath, buildId: "test-build-id", provider: provider() });
    let started = false;
    const starting = server.start().then(() => { started = true; });
    try {
      await new Promise<void>((resolve) => setTimeout(resolve, 30));
      expect(started).toBe(false);
    } finally {
      releaseLock();
      await Promise.all([starting.catch(() => undefined), heldLock]);
      await server.close();
    }

    expect(started).toBe(true);
    expect(existsSync(socketPath)).toBe(false);
  });

  it("waits for the socket lock before unlinking its bound path", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    const lockPath = join(root, "worker.sock.lock");
    const server = new YoloAutoWorkerServer({ socketPath, buildId: "test-build-id", provider: provider() });
    await server.start();

    let releaseLock!: () => void;
    let signalLockAcquired!: () => void;
    const lockAcquired = new Promise<void>((resolve) => { signalLockAcquired = resolve; });
    const heldLock = withFileLock(lockPath, async () => {
      await new Promise<void>((resolve) => {
        releaseLock = resolve;
        signalLockAcquired();
      });
    });
    await lockAcquired;

    let closed = false;
    const closing = server.close().then(() => { closed = true; });
    try {
      await new Promise<void>((resolve) => setTimeout(resolve, 30));
      expect(closed).toBe(false);
      expect(existsSync(socketPath)).toBe(true);
    } finally {
      releaseLock();
      await Promise.all([closing, heldLock]);
    }

    expect(closed).toBe(true);
    expect(existsSync(socketPath)).toBe(false);
  });

  it("preserves an active socket when closing after startup is rejected", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    const activeServer = net.createServer();
    await new Promise<void>((resolve) => activeServer.listen(socketPath, resolve));
    const blockedServer = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider(),
    });

    try {
      await expect(blockedServer.start()).rejects.toThrow(/already active/i);
      await blockedServer.close();
      expect(existsSync(socketPath)).toBe(true);
    } finally {
      await new Promise<void>((resolve) => activeServer.close(() => resolve()));
    }
  });

  it("replaces stale sockets and refuses active sockets", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");

    const staleServer = net.createServer();
    await new Promise<void>((resolve) => staleServer.listen(socketPath, resolve));
    await new Promise<void>((resolve) => staleServer.close(() => resolve()));
    const replacingServer = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider(),
    });
    await replacingServer.start();
    await replacingServer.close();

    const activeServer = net.createServer();
    await new Promise<void>((resolve) => activeServer.listen(socketPath, resolve));
    const blockedServer = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider(),
    });
    await expect(blockedServer.start()).rejects.toThrow(/already active/i);
    await new Promise<void>((resolve) => activeServer.close(() => resolve()));
  });

  it("closes idempotently and closes provider once", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let providerCloses = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      buildId: "test-build-id",
      provider: provider({ close: () => { providerCloses++; } }),
    });

    await server.start();
    await Promise.all([server.close(), server.close()]);

    expect(providerCloses).toBe(1);
    expect(existsSync(socketPath)).toBe(false);
  });
});
