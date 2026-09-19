import { mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createUnixSocketWorkerTransport, YoloAutoClient } from "./yolo-auto-client";
import { YoloAutoWorkerServer, type WorkerProvider } from "./yolo-auto-worker";

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function provider(overrides: Partial<WorkerProvider> = {}): WorkerProvider {
  return {
    warmL1: async () => undefined,
    evaluateL1: async () => ({ verdict: "safe", accepted: true, complete: true, degraded: false }),
    warmL2: async () => undefined,
    evaluateL2: async () => ({ results: [], escalated: false }),
    evaluateL3: async () => ({ recommendation: "prompt" }),
    ...overrides,
  };
}

describe("YoloAutoWorkerServer", () => {
  it("warms and serves L1 before L2 over a Unix socket", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let warmed = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      provider: provider({ warmL1: async () => { warmed++; } }),
    });
    await server.start();
    const client = new YoloAutoClient(createUnixSocketWorkerTransport(socketPath));

    await expect(client.evaluate({ toolName: "read", operation: "read" }, "l2")).resolves.toMatchObject({
      status: "complete",
      l1: { verdict: "safe" },
      escalated: false,
    });
    expect(warmed).toBe(1);

    client.close();
    await server.close();
  });

  it("replaces stale sockets and refuses active sockets", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");

    const staleServer = net.createServer();
    await new Promise<void>((resolve) => staleServer.listen(socketPath, resolve));
    await new Promise<void>((resolve) => staleServer.close(() => resolve()));
    const replacingServer = new YoloAutoWorkerServer({ socketPath, provider: provider() });
    await replacingServer.start();
    await replacingServer.close();

    const activeServer = net.createServer();
    await new Promise<void>((resolve) => activeServer.listen(socketPath, resolve));
    const blockedServer = new YoloAutoWorkerServer({ socketPath, provider: provider() });
    await expect(blockedServer.start()).rejects.toThrow(/already active/i);
    await new Promise<void>((resolve) => activeServer.close(() => resolve()));
  });

  it("reconnects a session client after worker replacement", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    const client = new YoloAutoClient(createUnixSocketWorkerTransport(socketPath));
    const request = { toolName: "read", operation: "read" };

    const firstServer = new YoloAutoWorkerServer({ socketPath, provider: provider() });
    await firstServer.start();
    await expect(client.evaluate(request, "l1")).resolves.toMatchObject({ status: "complete" });
    await firstServer.close();

    const replacementServer = new YoloAutoWorkerServer({ socketPath, provider: provider() });
    await replacementServer.start();
    await expect(client.evaluate(request, "l1")).resolves.toMatchObject({ status: "complete" });

    client.close();
    await replacementServer.close();
  });

  it("closes idempotently and closes provider once", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let providerCloses = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      provider: provider({ close: () => { providerCloses++; } }),
    });

    await server.start();
    await Promise.all([server.close(), server.close()]);

    expect(providerCloses).toBe(1);
    expect(existsSync(socketPath)).toBe(false);
  });

  it("fails closed when the request queue is full", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let started = false;
    let releaseEvaluation!: () => void;
    const evaluationReleased = new Promise<void>((resolve) => { releaseEvaluation = resolve; });
    const server = new YoloAutoWorkerServer({
      socketPath,
      queueLimit: 1,
      provider: provider({
        evaluateL1: async () => {
          started = true;
          await evaluationReleased;
          return { verdict: "safe", accepted: true, complete: true, degraded: false };
        },
      }),
    });
    await server.start();
    const transport = createUnixSocketWorkerTransport(socketPath);
    const request = (requestId: string) => transport.request({
      protocolVersion: 1,
      requestId,
      phase: "l1",
      deadlineMs: 2_000,
      payload: { toolName: "read", operation: "read" },
    });

    const first = request("first");
    while (!started) await new Promise((resolve) => setTimeout(resolve, 0));
    const queued = request("queued");
    const overflow = await request("overflow");
    expect(overflow).toMatchObject({ requestId: "overflow", completion: "failed", error: "queue_overflow" });
    releaseEvaluation();
    await expect(first).resolves.toMatchObject({ requestId: "first", completion: "complete" });
    await expect(queued).resolves.toMatchObject({ requestId: "queued", completion: "complete" });

    transport.close?.();
    await server.close();
  });

  it("shares one warmed worker across two session clients", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let l3Warmups = 0;
    let l3Evaluations = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      provider: provider({
        evaluateL2: async () => ({ results: [], escalated: true }),
        warmL3: async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          l3Warmups++;
        },
        evaluateL3: async () => {
          l3Evaluations++;
          return { recommendation: "prompt" };
        },
      }),
    });
    await server.start();
    const clients = [
      new YoloAutoClient(createUnixSocketWorkerTransport(socketPath)),
      new YoloAutoClient(createUnixSocketWorkerTransport(socketPath)),
    ];

    const results = await Promise.all(clients.map((client) =>
      client.evaluate({ toolName: "read", operation: "read" }, "l3"),
    ));
    expect(results).toHaveLength(2);
    expect(results).toEqual([
      expect.objectContaining({ status: "complete", escalated: true, l3: { recommendation: "prompt" } }),
      expect.objectContaining({ status: "complete", escalated: true, l3: { recommendation: "prompt" } }),
    ]);
    expect(l3Warmups).toBe(1);
    expect(l3Evaluations).toBe(2);

    clients.forEach((client) => client.close());
    await server.close();
  });

  it("loads L3 only after explicit L2 escalation", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-worker-"));
    tempRoots.push(root);
    const socketPath = join(root, "worker.sock");
    let l3Warmups = 0;
    const server = new YoloAutoWorkerServer({
      socketPath,
      provider: provider({
        evaluateL2: async () => ({ results: [], escalated: true }),
        warmL3: async () => { l3Warmups++; },
      }),
    });
    await server.start();
    const client = new YoloAutoClient(createUnixSocketWorkerTransport(socketPath));

    await expect(client.evaluate({ toolName: "read", operation: "read" }, "l3")).resolves.toMatchObject({
      status: "complete",
      escalated: true,
      l3: { recommendation: "prompt" },
    });
    expect(l3Warmups).toBe(1);

    client.close();
    await server.close();
  });
});
