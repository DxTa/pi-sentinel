import { mkdtemp, rm } from "node:fs/promises";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { isUnixSocketActive } from "./yolo-auto-startup";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("isUnixSocketActive", () => {
  it("distinguishes missing, stale, and active Unix sockets", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-yolo-startup-"));
    roots.push(root);
    const socketPath = join(root, "worker.sock");

    await expect(isUnixSocketActive(socketPath)).resolves.toBe(false);

    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await expect(isUnixSocketActive(socketPath)).resolves.toBe(false);

    const activeServer = net.createServer();
    await new Promise<void>((resolve) => activeServer.listen(socketPath, resolve));
    await expect(isUnixSocketActive(socketPath)).resolves.toBe(true);
    await new Promise<void>((resolve) => activeServer.close(() => resolve()));
  });
});
