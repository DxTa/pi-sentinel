import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, describe, expect, it, vi } from "vitest";

import { AutoModeClient, createUnixSocketWorkerTransport } from "./auto-mode-client";
import type { AutoModeHeads } from "./auto-mode-policy";
import { AutoModeWorkerServer, type WorkerProvider } from "./auto-mode-worker";

const BUILD_ID = "pi-sentinel-test:model-r1";
const TEXT = "tool=read_file path=src/index.ts";
const roots: string[] = [];
const heads: AutoModeHeads = {
  injection: { injection: 0.01 },
  threat: { benign: 0.99 },
  tool_class: { files: 1 },
  tool_action: { read: 1 },
  tool_tags: { "source:sensitive": 0, "source:untrusted": 0, "sink:external": 0 },
  sensitive_document: { none: 1 },
  routing: { local: 1 },
};

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function provider(overrides: Partial<WorkerProvider> = {}): WorkerProvider {
  return { ready: async () => undefined, classify: async () => heads, ...overrides };
}

function completeResponse(request: { requestId: string }, overrides: Record<string, unknown> = {}) {
  return {
    type: "classify",
    protocolVersion: 2,
    requestId: request.requestId,
    status: "complete",
    heads,
    ...overrides,
  };
}

describe("AutoModeClient protocol v2", () => {
  it("sends one classify request and returns all heads", async () => {
    const requests: Record<string, unknown>[] = [];
    const transport = {
      waitUntilReady: vi.fn(async () => BUILD_ID),
      request: vi.fn(async (request: Record<string, unknown>) => {
        requests.push(request);
        return completeResponse(request as { requestId: string });
      }),
      shutdownWorker: vi.fn(async () => undefined),
    };
    const client = new AutoModeClient(transport, { expectedBuildId: BUILD_ID });

    const result = await client.evaluate(TEXT);

    expect(result).toMatchObject({ status: "complete", heads, buildId: BUILD_ID });
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      type: "classify",
      protocolVersion: 2,
      requestId: result.evaluationId,
      deadlineMs: expect.any(Number),
      text: TEXT,
    });
  });

  it("fails closed on worker-declared errors without exposing their text", async () => {
    const transport = {
      waitUntilReady: async () => BUILD_ID,
      request: async (request: Record<string, unknown>) => completeResponse(
        request as { requestId: string },
        { status: "failed", error: "private worker diagnostic" },
      ),
      shutdownWorker: async () => undefined,
    };
    const client = new AutoModeClient(transport, { expectedBuildId: BUILD_ID });

    const result = await client.evaluate(TEXT);

    expect(result).toMatchObject({ status: "unavailable", reason: "worker_failed" });
    expect(JSON.stringify(result)).not.toContain("private worker diagnostic");
  });

  it("fails closed on a mismatched response id", async () => {
    const transport = {
      waitUntilReady: async () => BUILD_ID,
      request: async () => completeResponse({ requestId: "different" }),
      shutdownWorker: async () => undefined,
    };
    const client = new AutoModeClient(transport, { expectedBuildId: BUILD_ID });

    await expect(client.evaluate(TEXT)).resolves.toMatchObject({
      status: "unavailable",
      reason: "protocol_mismatch",
    });
  });

  it("fails closed when classification exceeds its deadline", async () => {
    const transport = {
      waitUntilReady: async () => BUILD_ID,
      request: () => new Promise(() => undefined),
      shutdownWorker: async () => undefined,
    };
    const client = new AutoModeClient(transport, {
      expectedBuildId: BUILD_ID,
      requestTimeoutMs: 5,
    });

    await expect(client.evaluate(TEXT)).resolves.toMatchObject({
      status: "unavailable",
      reason: "request_failed",
    });
  });

  it("shuts down a mismatched worker before reporting its build ID", async () => {
    const shutdownWorker = vi.fn(async () => undefined);
    const transport = {
      waitUntilReady: async () => "old-build",
      request: vi.fn(),
      shutdownWorker,
    };
    const client = new AutoModeClient(transport, { expectedBuildId: BUILD_ID });

    await expect(client.waitUntilReady()).rejects.toMatchObject({ name: "AutoModeBuildMismatchError" });
    expect(shutdownWorker).toHaveBeenCalledOnce();
  });

  it("keeps the shared worker available after a client closes", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-client-close-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");
    const classify = vi.fn(async () => heads);
    const worker = new AutoModeWorkerServer({
      socketPath,
      buildId: BUILD_ID,
      provider: provider({ classify }),
    });
    await worker.start();
    const firstClient = new AutoModeClient(createUnixSocketWorkerTransport(socketPath), {
      expectedBuildId: BUILD_ID,
    });
    const nextClient = new AutoModeClient(createUnixSocketWorkerTransport(socketPath), {
      expectedBuildId: BUILD_ID,
    });

    try {
      await expect(firstClient.evaluate(TEXT)).resolves.toMatchObject({ status: "complete", buildId: BUILD_ID });
      firstClient.close();
      await expect(nextClient.evaluate(TEXT)).resolves.toMatchObject({ status: "complete", buildId: BUILD_ID });
      expect(classify).toHaveBeenCalledTimes(2);
    } finally {
      firstClient.close();
      nextClient.close();
      await worker.close();
    }
  });

  it("replaces a mismatched worker and classifies through the replacement", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-client-v2-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");
    let markOldClosed!: () => void;
    const oldClosed = new Promise<void>((resolve) => { markOldClosed = resolve; });
    const oldWorker = new AutoModeWorkerServer({
      socketPath,
      buildId: "old-build",
      provider: provider({ close: markOldClosed }),
    });
    await oldWorker.start();
    const client = new AutoModeClient(createUnixSocketWorkerTransport(socketPath), {
      expectedBuildId: BUILD_ID,
    });
    let replacement: AutoModeWorkerServer | undefined;

    try {
      await expect(client.waitUntilReady()).rejects.toMatchObject({ name: "AutoModeBuildMismatchError" });
      await oldClosed;
      replacement = new AutoModeWorkerServer({ socketPath, buildId: BUILD_ID, provider: provider() });
      await replacement.start();

      await expect(client.evaluate(TEXT)).resolves.toMatchObject({
        status: "complete",
        buildId: BUILD_ID,
        heads,
      });
    } finally {
      client.close();
      await oldWorker.close();
      await replacement?.close();
    }
  });
});
