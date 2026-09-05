import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { createServer } from "node:net";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { detectExternalPaths } from "./external-path-gate.js";
import { validateSandboxGrantPath } from "./settings.js";

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

describe("detectExternalPaths", () => {
  it("rejects broad system roots instead of offering generic path approval", async () => {
    const workspace = await mkdtemp(path.join("/tmp", "pi-external-workspace-"));
    tempPaths.push(workspace);

    expect(() => detectExternalPaths(
      "cat /var",
      workspace,
      {
        name: "offline-dev",
        network: false,
        roBinds: [],
        rwBinds: [],
        env: { allow: [], deny: [] },
        maskedPaths: [],
      },
      undefined,
      () => workspace,
    )).toThrow(/broad|sensitive/i);
  });

  it("rejects directories containing privileged socket locations", async () => {
    expect(() => validateSandboxGrantPath("/run")).toThrow(/socket|protected/i);
  });

  it("does not re-prompt for an explicitly unmasked path", async () => {
    const workspace = await mkdtemp(path.join("/tmp", "pi-external-workspace-"));
    const outside = await mkdtemp(path.join("/tmp", "pi-external-outside-"));
    tempPaths.push(workspace, outside);
    const approvedPath = path.join(outside, ".env");
    await writeFile(approvedPath, "test", "utf8");

    expect(detectExternalPaths(
      `cat ${approvedPath}`,
      workspace,
      {
        name: "offline-dev",
        network: false,
        roBinds: [],
        rwBinds: [],
        env: { allow: [], deny: [] },
        maskedPaths: [],
      },
      undefined,
      () => workspace,
      [approvedPath],
    )).toEqual([]);
  });

  it("rejects Unix sockets instead of offering generic path approval", async () => {
    const workspace = await mkdtemp(path.join("/tmp", "pi-external-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-socket-"));
    tempPaths.push(workspace, outside);
    const socketPath = path.join(outside, "docker.sock");
    const server = createServer();

    try {
      await new Promise<void>((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(socketPath, resolveListen);
      });

      expect(() => detectExternalPaths(
        `cat ${socketPath}`,
        workspace,
        {
          name: "offline-dev",
          network: false,
          roBinds: [],
          rwBinds: [],
          env: { allow: [], deny: [] },
          maskedPaths: [],
        },
        undefined,
        () => workspace,
      )).toThrow(/special|socket/i);
    } finally {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    }
  });
});
