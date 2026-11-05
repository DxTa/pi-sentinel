import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { createServer } from "node:net";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { detectExternalPaths, detectExternalWritePaths, extractPathTokens } from "./external-path-gate.js";
import { validateSandboxGrantPath } from "./settings.js";

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

describe("detectExternalPaths", () => {
  it("ignores slash-only comment markers but keeps real root paths", () => {
    expect(extractPathTokens("python3 - <<'EOF'\nx = 1  " + "/".repeat(2) + " note\nEOF")).toEqual([]);
    expect(extractPathTokens("ls /")).toEqual(["/"]);
  });

  it("does not treat sed substitution delimiters as a broad path grant", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-workspace-"));
    tempPaths.push(workspace);
    const envPath = path.join(workspace, ".env.local");
    await writeFile(envPath, "TOKEN=secret-value\n", "utf8");
    const profile = {
      name: "offline-dev",
      network: false,
      roBinds: [],
      rwBinds: [],
      env: { allow: [], deny: [] },
      maskedPaths: [],
    };

    await expect(Promise.resolve().then(() => detectExternalPaths(
      `cat ${envPath} | sed 's/=/: /'`,
      workspace,
      profile,
      undefined,
      () => workspace,
    ))).resolves.toEqual([]);
  });

  it("still rejects an explicit filesystem root argument", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-workspace-"));
    tempPaths.push(workspace);
    const profile = {
      name: "offline-dev",
      network: false,
      roBinds: [],
      rwBinds: [],
      env: { allow: [], deny: [] },
      maskedPaths: [],
    };

    await expect(Promise.resolve().then(() => detectExternalPaths(
      "ls /",
      workspace,
      profile,
      undefined,
      () => workspace,
    ))).rejects.toThrow(/broad|sensitive/i);
  });

  it("rejects broad system roots instead of offering generic path approval", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-workspace-"));
    tempPaths.push(workspace);

    await expect(detectExternalPaths(
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
    )).rejects.toThrow(/broad|sensitive/i);
  });

  it("allows granting socket locations", async () => {
    expect(() => validateSandboxGrantPath("/run")).not.toThrow();
  });

  it("does not re-prompt for an explicitly unmasked path", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-workspace-"));
    const outside = await mkdtemp(path.join(tmpdir(), "pi-external-outside-"));
    tempPaths.push(workspace, outside);
    const approvedPath = path.join(outside, ".env");
    await writeFile(approvedPath, "test", "utf8");

    await expect(detectExternalPaths(
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
    )).resolves.toEqual([]);
  });

  it("offers path approval for Unix sockets like any other path", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-socket-"));
    tempPaths.push(workspace, outside);
    const socketPath = path.join(outside, "docker.sock");
    const server = createServer();

    try {
      await new Promise<void>((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(socketPath, resolveListen);
      });

      await expect(detectExternalPaths(
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
      )).resolves.toBeDefined();
    } finally {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    }
  });
});


describe("detectExternalWritePaths", () => {
  it("requests write access even when an external target is already read-visible", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-write-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-write-"));
    tempPaths.push(workspace, outside);
    const target = path.join(outside, "existing.txt");
    await writeFile(target, "before", "utf8");
    const profile = {
      name: "offline-dev",
      network: false,
      roBinds: [outside],
      rwBinds: [],
      env: { allow: [], deny: [] },
      maskedPaths: [],
    };

    await expect(detectExternalWritePaths(
      `printf value > ${target}`,
      workspace,
      profile,
      undefined,
      () => workspace,
    )).resolves.toEqual([{ path: target, isDirectory: false, displayPath: target }]);
  });

  it("does not offer generic write access to masked credentials", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-write-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-write-"));
    tempPaths.push(workspace, outside);
    const target = path.join(outside, ".env");
    await writeFile(target, "SECRET=value", "utf8");

    await expect(detectExternalWritePaths(
      "printf value > " + target,
      workspace,
      {
        name: "offline-dev",
        network: false,
        roBinds: [],
        rwBinds: [],
        env: { allow: [], deny: [] },
        maskedPaths: ["**/.env"],
      },
      undefined,
      () => workspace,
    )).resolves.toEqual([]);
  });
  it("grants nearest existing parent for missing output targets", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-write-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-write-"));
    tempPaths.push(workspace, outside);
    const target = path.join(outside, "not-created-yet", "output.txt");

    await expect(detectExternalWritePaths(
      "printf value > " + target,
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
    )).resolves.toEqual([{ path: outside, isDirectory: true, displayPath: outside }]);
  });

  it("rejects masked names for missing output targets", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-write-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-write-"));
    tempPaths.push(workspace, outside);
    const target = path.join(outside, ".env");

    await expect(detectExternalWritePaths(
      "printf value > " + target,
      workspace,
      {
        name: "offline-dev",
        network: false,
        roBinds: [],
        rwBinds: [],
        env: { allow: [], deny: [] },
        maskedPaths: ["**/.env"],
      },
      undefined,
      () => workspace,
    )).rejects.toThrow(/masked.*write target/i);
  });

  it("rejects missing output targets below dangling symlinks", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-write-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-write-"));
    tempPaths.push(workspace, outside);
    const danglingLink = path.join(outside, "dangling");
    await symlink(path.join(outside, "not-created"), danglingLink);
    const target = path.join(danglingLink, "output.txt");

    await expect(detectExternalWritePaths(
      "printf value > " + target,
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
    )).rejects.toThrow(/unresolved symlink/i);
  });

  it("does not request write access when target is already writable", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "pi-external-write-workspace-"));
    const outside = await mkdtemp(path.join(homedir(), ".pi-external-write-"));
    tempPaths.push(workspace, outside);
    const target = path.join(outside, "existing.txt");
    await writeFile(target, "before", "utf8");

    await expect(detectExternalWritePaths(
      `printf value > ${target}`,
      workspace,
      {
        name: "offline-dev",
        network: false,
        roBinds: [],
        rwBinds: [outside],
        env: { allow: [], deny: [] },
        maskedPaths: [],
      },
      undefined,
      () => workspace,
    )).resolves.toEqual([]);
  });
});
