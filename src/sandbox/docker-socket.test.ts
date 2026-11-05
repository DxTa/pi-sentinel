import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveDockerSocketPaths } from "./docker-socket.js";

const servers: Server[] = [];
const dirs: string[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(servers.splice(0).map((server) => new Promise((done) => server.close(done))));
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

async function listen(path: string): Promise<void> {
  const server = createServer();
  servers.push(server);
  await new Promise<void>((done) => server.listen(path, done));
}

async function fakeHome(): Promise<string> {
  const home = mkdtempSync(join(tmpdir(), "pi-sock-home-"));
  dirs.push(home);
  vi.stubEnv("HOME", home);
  return home;
}

describe("resolveDockerSocketPaths", () => {
  it("finds a Rancher Desktop socket under the home directory", async () => {
    const home = await fakeHome();
    mkdirSync(join(home, ".rd"));
    const socket = join(home, ".rd", "docker.sock");
    await listen(socket);

    expect(resolveDockerSocketPaths([socket])).toContain(socket);
  });

  it("follows a symlink to a socket", async () => {
    const home = await fakeHome();
    mkdirSync(join(home, ".rd"));
    mkdirSync(join(home, ".docker", "run"), { recursive: true });
    const target = join(home, ".rd", "docker.sock");
    const link = join(home, ".docker", "run", "docker.sock");
    await listen(target);
    symlinkSync(target, link);

    expect(resolveDockerSocketPaths([link])).toEqual(expect.arrayContaining([link]));
  });

  it("ignores unknown locations and missing sockets", async () => {
    const home = await fakeHome();
    expect(resolveDockerSocketPaths([join(home, "elsewhere", "docker.sock"), join(home, ".rd", "docker.sock")])).toEqual([]);
  });
});
