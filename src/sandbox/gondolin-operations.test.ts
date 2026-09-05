import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createGondolinBackend } from "./backends/gondolin-backend.js";
import { createGondolinOperations } from "./gondolin-operations.js";
import type {
  GondolinRuntime,
  GondolinRuntimeOperations,
  GondolinRuntimeSession,
  GondolinSession,
  GondolinSessionPolicy,
} from "./gondolin-session.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function makePolicy(workspaceRoot: string): GondolinSessionPolicy {
  return { vfs: { workspaceRoot, sensitivePaths: ["**/.env"] }, network: { allowedDomains: [] } };
}

async function makeSession(
  root: string,
  operations?: GondolinRuntimeOperations,
): Promise<GondolinSession> {
  const runtime: GondolinRuntime = {
    createSession: async (): Promise<GondolinRuntimeSession> => ({ close: vi.fn(), operations }),
  };
  return createGondolinBackend({ runtime }).createSession({
    image: "gondolin:test",
    workspaceRoot: root,
    policy: makePolicy(root),
  });
}

function makeVmOperations(overrides: Partial<GondolinRuntimeOperations> = {}): GondolinRuntimeOperations {
  return {
    exec: vi.fn(async (_command, _cwd, options) => {
      options.onData(Buffer.from("vm output\n"));
      return { exitCode: 0 };
    }),
    fs: {
      access: vi.fn(async () => undefined),
      readFile: vi.fn(async () => Buffer.from("vm content")),
      writeFile: vi.fn(async () => undefined),
      mkdir: vi.fn(async () => undefined),
    },
    ...overrides,
  };
}

describe("createGondolinOperations", () => {
  it("routes Bash and ordinary reads through the active VM without host fallback", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-");
    roots.push(root);
    await writeFile(join(root, "safe.txt"), "host content");
    await writeFile(join(root, "..foo"), "host content");
    await writeFile(join(root, "a\\\\b"), "host content");
    await writeFile(join(root, "..\\\\outside"), "host content");
    const vm = makeVmOperations();
    const operations = createGondolinOperations(await makeSession(root, vm));
    const chunks: Buffer[] = [];

    await expect(operations.read.readFile(join(root, "safe.txt"))).resolves.toEqual(Buffer.from("vm content"));
    await expect(operations.bash.exec("printf vm", root, { onData: (data) => chunks.push(data) })).resolves.toEqual({ exitCode: 0 });

    await expect(operations.read.readFile(join(root, "..foo"))).resolves.toEqual(Buffer.from("vm content"));
    await expect(operations.read.readFile(join(root, "a\\\\b"))).resolves.toEqual(Buffer.from("vm content"));
    await expect(operations.read.readFile(join(root, "..\\\\outside"))).resolves.toEqual(Buffer.from("vm content"));
    expect(vm.fs.readFile).toHaveBeenCalledWith("/workspace/safe.txt");
    expect(vm.fs.readFile).toHaveBeenCalledWith("/workspace/..foo");
    expect(vm.fs.readFile).toHaveBeenCalledWith("/workspace/a\\\\b");
    expect(vm.fs.readFile).toHaveBeenCalledWith("/workspace/..\\\\outside");
    expect(vm.exec).toHaveBeenCalledWith("printf vm", "/workspace", expect.any(Object));
    expect(Buffer.concat(chunks).toString()).toBe("vm output\n");
  });

  it("returns (masked) for sensitive reads without reading host or VM contents", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-secret-");
    roots.push(root);
    await writeFile(join(root, ".env"), "SECRET=host-secret");
    const vm = makeVmOperations();
    const session = await makeSession(root, vm);
    const operations = createGondolinOperations(session);

    await expect(operations.read.readFile(join(root, ".env"))).resolves.toEqual(Buffer.from("(masked)"));
    expect(vm.fs.readFile).not.toHaveBeenCalled();
  });

  it("routes ordinary edit reads through the VM without host fallback", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-edit-read-");
    roots.push(root);
    await writeFile(join(root, "safe.txt"), "host content");
    const vm = makeVmOperations();
    const operations = createGondolinOperations(await makeSession(root, vm));

    await expect(operations.edit.access(join(root, "safe.txt"))).resolves.toBeUndefined();
    await expect(operations.edit.readFile(join(root, "safe.txt"))).resolves.toEqual(Buffer.from("vm content"));
    expect(vm.fs.access).toHaveBeenCalledWith("/workspace/safe.txt");
    expect(vm.fs.readFile).toHaveBeenCalledWith("/workspace/safe.txt");
  });

  it("masks sensitive edit reads without reading host or VM contents", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-edit-secret-");
    roots.push(root);
    await writeFile(join(root, ".env"), "SECRET=host-secret");
    const vm = makeVmOperations();
    const operations = createGondolinOperations(await makeSession(root, vm));

    await expect(operations.edit.access(join(root, ".env"))).resolves.toBeUndefined();
    await expect(operations.edit.readFile(join(root, ".env"))).resolves.toEqual(Buffer.from("(masked)"));
    expect(vm.fs.access).not.toHaveBeenCalled();
    expect(vm.fs.readFile).not.toHaveBeenCalled();
  });

  it("provides display-only edit preview without VM or host file reads", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-preview-");
    roots.push(root);
    const vm = makeVmOperations();
    const operations = createGondolinOperations(await makeSession(root, vm));

    await expect(operations.edit.preview(join(root, "safe.txt"), "new content")).resolves.toEqual({
      mode: "display-only",
      path: "/workspace/safe.txt",
      content: "new content",
    });
    expect(vm.fs.access).not.toHaveBeenCalled();
    expect(vm.fs.readFile).not.toHaveBeenCalled();
  });

  it("denies sensitive edit preview without reading host or VM contents", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-preview-secret-");
    roots.push(root);
    await writeFile(join(root, ".env"), "SECRET=host-secret");
    const vm = makeVmOperations();
    const operations = createGondolinOperations(await makeSession(root, vm));

    await expect(operations.edit.preview(join(root, ".env"), "new content")).rejects.toMatchObject({ code: "denied" });
    expect(vm.fs.access).not.toHaveBeenCalled();
    expect(vm.fs.readFile).not.toHaveBeenCalled();
  });

  it("writes and edits ordinary workspace files through the VM", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-deny-");
    roots.push(root);
    await mkdir(join(root, "src"));
    const vm = makeVmOperations();
    const session = await makeSession(root, vm);
    const operations = createGondolinOperations(session);

    await expect(operations.write.writeFile(join(root, "src", "new.ts"), "x")).resolves.toBeUndefined();
    await expect(operations.write.mkdir(join(root, "src", "new-dir"))).resolves.toBeUndefined();
    await expect(operations.edit.writeFile(join(root, "src", "new.ts"), "x")).resolves.toBeUndefined();
    expect(vm.fs.writeFile).toHaveBeenCalledWith("/workspace/src/new.ts", "x");
    expect(vm.fs.mkdir).toHaveBeenCalledWith("/workspace/src/new-dir", { recursive: true });
  });

  it("creates existing workspace directories recursively for Pi write compatibility", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-existing-dir-");
    roots.push(root);
    const vm = makeVmOperations();
    const operations = createGondolinOperations(await makeSession(root, vm));

    await expect(operations.write.mkdir(root)).resolves.toBeUndefined();
    expect(vm.fs.mkdir).toHaveBeenCalledWith("/workspace", { recursive: true });
  });

  it("denies symlink escapes without host fallback", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-symlink-");
    const outside = await mkdtemp("/tmp/gondolin-operations-outside-");
    roots.push(root, outside);
    await symlink(outside, join(root, "escape"));
    const vm = makeVmOperations();
    const operations = createGondolinOperations(await makeSession(root, vm));

    await expect(operations.read.readFile(join(root, "escape", "secret.txt"))).rejects.toMatchObject({ code: "denied" });
    expect(vm.fs.readFile).not.toHaveBeenCalled();
  });

  it("denies when the VM operation surface is unavailable or the session is closed", async () => {
    const root = await mkdtemp("/tmp/gondolin-operations-lifecycle-");
    roots.push(root);
    const unavailable = await makeSession(root);
    await expect(createGondolinOperations(unavailable).read.readFile(join(root, "safe.txt")))
      .rejects.toMatchObject({ code: "session-unavailable" });

    const session = await makeSession(root, makeVmOperations());
    const operations = createGondolinOperations(session);
    await session.close();
    await expect(operations.bash.exec("true", root, { onData: vi.fn() }))
      .rejects.toMatchObject({ code: "closed" });
  });
});
