import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  createGondolinBackend,
  type GondolinRuntime,
  type GondolinRuntimeSession,
} from "./backends/gondolin-backend.js";
import {
  GondolinSessionError,
  type GondolinSessionPolicy,
} from "./gondolin-session.js";

async function makeWorkspace(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "gondolin-backend-"));
  await mkdir(join(root, "src"));
  await writeFile(join(root, ".env"), "SECRET=value");
  await writeFile(join(root, "src", "index.ts"), "export {};");
  return root;
}

function makeRuntime(): {
  runtime: GondolinRuntime;
  createSession: ReturnType<typeof vi.fn>;
  closeSession: ReturnType<typeof vi.fn>;
} {
  const closeSession = vi.fn(async () => undefined);
  const runtimeSession: GondolinRuntimeSession = { close: closeSession };
  const createSession = vi.fn(async () => runtimeSession);
  return { runtime: { createSession }, createSession, closeSession };
}

function makePolicy(workspaceRoot: string): GondolinSessionPolicy {
  return {
    vfs: { workspaceRoot, sensitivePaths: ["**/.env"] },
    network: { allowedDomains: ["api.example.com"] },
  };
}

describe("createGondolinBackend", () => {
  it("creates a runtime from the effective workspace when a factory is supplied", async () => {
    const workspaceRoot = await makeWorkspace();
    try {
      const harness = makeRuntime();
      const runtimeFactory = vi.fn(() => harness.runtime);
      const backend = createGondolinBackend({ runtimeFactory });
      await backend.createSession({
        image: "gondolin:test",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
      });
      expect(runtimeFactory).toHaveBeenCalledWith({
        image: "gondolin:test",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
      });
      expect(harness.createSession).toHaveBeenCalledTimes(1);
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it("applies policy hooks before exposing the workspace to the runtime", async () => {
    const workspaceRoot = await makeWorkspace();
    try {
      const { runtime, createSession } = makeRuntime();
      const backend = createGondolinBackend({ runtime });
      const session = await backend.createSession({
        image: "gondolin:test",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
        environment: { UV_OFFLINE: "1" },
      });

      expect(createSession).toHaveBeenCalledTimes(1);
      const runtimeOptions = createSession.mock.calls[0]![0];
      expect(runtimeOptions).not.toHaveProperty("workspaceRoot");
      expect(runtimeOptions.environment).toEqual({ UV_OFFLINE: "1" });
      expect(runtimeOptions.workspace).toMatchObject({ kind: "gondolin-policy-vfs" });
      expect(runtimeOptions.workspace.vfs.read({ operation: "read", path: ".env" })).toMatchObject({
        decision: "placeholder",
        content: "(masked)",
      });
      expect(runtimeOptions.workspace.vfs.mutate({ operation: "write", path: "src/index.ts" })).toMatchObject({
        decision: "allow",
      });
      expect(session.generation).toBe(1);
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it("passes read-only global mount policy to the runtime", async () => {
    const workspaceRoot = await makeWorkspace();
    const globalRoot = await mkdtemp(join(tmpdir(), "gondolin-global-"));
    try {
      const { runtime, createSession } = makeRuntime();
      const backend = createGondolinBackend({ runtime });
      await backend.createSession({
        image: "gondolin:test",
        workspaceRoot,
        policy: {
          ...makePolicy(workspaceRoot),
          mounts: [{
            guestPath: "/root",
            readOnly: true,
            vfs: { workspaceRoot: globalRoot, sensitivePaths: [".npmrc"] },
          }],
        },
      });

      const runtimeOptions = createSession.mock.calls[0]![0];
      expect(runtimeOptions.mounts).toEqual([{
        guestPath: "/root",
        hostRoot: realpathSync.native(globalRoot),
        readOnly: true,
        workspace: expect.objectContaining({ kind: "gondolin-policy-vfs" }),
      }]);
      expect(runtimeOptions.mounts[0].workspace.vfs.read({ operation: "read", path: ".npmrc" })).toMatchObject({
        decision: "placeholder",
        content: "(masked)",
      });
      expect(runtimeOptions.mounts[0].workspace.vfs.mutate({ operation: "write", path: "cache/file" })).toMatchObject({
        decision: "allow",
      });
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
      await rm(globalRoot, { recursive: true, force: true });
    }
  });

  it("rejects read-write host mounts and routes reserved broker paths", async () => {
    const workspaceRoot = await makeWorkspace();
    const sourceRoot = await mkdtemp(join(tmpdir(), "gondolin-global-invalid-"));
    try {
      const harness = makeRuntime();
      const backend = createGondolinBackend({ runtime: harness.runtime });
      for (const guestPath of ["/root", "/mnt/approved", "/mnt/approved/m1"]) {
        await expect(backend.createSession({
          image: "image",
          workspaceRoot,
          policy: {
            ...makePolicy(workspaceRoot),
            mounts: [{
              guestPath,
              readOnly: guestPath !== "/root",
              vfs: { workspaceRoot: sourceRoot },
            }],
          },
        })).rejects.toMatchObject({ code: "policy-unavailable" });
      }
      expect(harness.createSession).not.toHaveBeenCalled();
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
      await rm(sourceRoot, { recursive: true, force: true });
    }
  });

  it("rejects global mounts that normalize onto workspace", async () => {
    const workspaceRoot = await makeWorkspace();
    const globalRoot = await mkdtemp(join(tmpdir(), "gondolin-global-invalid-"));
    try {
      const harness = makeRuntime();
      const backend = createGondolinBackend({ runtime: harness.runtime });
      await expect(backend.createSession({
        image: "image",
        workspaceRoot,
        policy: {
          ...makePolicy(workspaceRoot),
          mounts: [{
            guestPath: "/root/../workspace",
            readOnly: true,
            vfs: { workspaceRoot: globalRoot },
          }],
        },
      })).rejects.toMatchObject({ code: "policy-unavailable" });
      expect(harness.createSession).not.toHaveBeenCalled();
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
      await rm(globalRoot, { recursive: true, force: true });
    }
  });

  it.each([
    ["runtime", (workspaceRoot: string) => ({ image: "image", workspaceRoot, policy: makePolicy(workspaceRoot) })],
    ["image", (workspaceRoot: string) => ({ image: "", workspaceRoot, policy: makePolicy(workspaceRoot) })],
    ["workspace", (_workspaceRoot: string) => ({ image: "image", workspaceRoot: "/does/not/exist", policy: makePolicy("/does/not/exist") })],
    ["policy", (workspaceRoot: string) => ({ image: "image", workspaceRoot, policy: undefined })],
  ] as const)("fails closed when %s is unavailable", async (missing, makeInput) => {
    const workspaceRoot = await makeWorkspace();
    try {
      const runtimeHarness = makeRuntime();
      const backend = createGondolinBackend(missing === "runtime" ? {} : { runtime: runtimeHarness.runtime });
      await expect(backend.createSession(makeInput(workspaceRoot))).rejects.toThrow(GondolinSessionError);
      expect(runtimeHarness.createSession).not.toHaveBeenCalled();
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it.each([
    ["null", null],
    ["missing close", {}],
  ] as const)("fails closed when runtime returns an invalid %s session", async (_label, runtimeSession) => {
    const workspaceRoot = await makeWorkspace();
    try {
      const runtime: GondolinRuntime = {
        createSession: vi.fn(async () => runtimeSession as GondolinRuntimeSession),
      };
      await expect(
        createGondolinBackend({ runtime }).createSession({
          image: "image",
          workspaceRoot,
          policy: makePolicy(workspaceRoot),
        }),
      ).rejects.toMatchObject({ code: "session-unavailable" });
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it("fails closed when runtime session creation rejects", async () => {
    const workspaceRoot = await makeWorkspace();
    try {
      const runtime: GondolinRuntime = {
        createSession: vi.fn(async () => {
          throw new Error("runtime unavailable");
        }),
      };
      await expect(
        createGondolinBackend({ runtime }).createSession({
          image: "image",
          workspaceRoot,
          policy: makePolicy(workspaceRoot),
        }),
      ).rejects.toThrow("runtime unavailable");
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it("adds an approved read-only source through the host-only session capability", async () => {
    const workspaceRoot = await makeWorkspace();
    const sourceRoot = await mkdtemp(join(tmpdir(), "gondolin-source-"));
    try {
      const closeSession = vi.fn(async () => undefined);
      const addReadOnlySource = vi.fn(async () => "/m1");
      const runtime: GondolinRuntime = {
        createSession: vi.fn(async () => ({ close: closeSession, addReadOnlySource })),
      };
      const session = await createGondolinBackend({ runtime }).createSession({
        image: "image",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
      });

      await expect(session.addReadOnlySource({
        hostRoot: sourceRoot,
        vfs: { workspaceRoot: sourceRoot, sensitivePaths: [".env"] },
      })).resolves.toBe("/m1");
      expect(addReadOnlySource).toHaveBeenCalledWith({
        hostRoot: realpathSync.native(sourceRoot),
        identity: expect.any(String),
        workspace: expect.objectContaining({ kind: "gondolin-policy-vfs" }),
      });
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
      await rm(sourceRoot, { recursive: true, force: true });
    }
  });

  it("rejects dynamic sources that expose filesystem or host-home roots", async () => {
    const workspaceRoot = await makeWorkspace();
    const aliasRoot = join(tmpdir(), `gondolin-source-alias-${Date.now()}`);
    try {
      await symlink(join(homedir(), ".pi"), aliasRoot);
      const addReadOnlySource = vi.fn(async () => "/m1");
      const runtime: GondolinRuntime = {
        createSession: vi.fn(async () => ({ close: vi.fn(), addReadOnlySource })),
      };
      const session = await createGondolinBackend({ runtime }).createSession({
        image: "image",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
      });

      for (const hostRoot of [
        "/",
        homedir(),
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/etc",
        "/root",
        "/tmp",
        "/var",
        aliasRoot,
        join(homedir(), ".pi"),
        join(homedir(), ".ssh"),
      ]) {
        await expect(session.addReadOnlySource({
          hostRoot,
          vfs: { workspaceRoot: hostRoot },
        })).rejects.toMatchObject({ code: "policy-unavailable" });
      }
      expect(addReadOnlySource).not.toHaveBeenCalled();
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
      await rm(aliasRoot, { force: true });
    }
  });

  it("closes idempotently and rejects closed or stale-generation operations without fallback", async () => {
    const workspaceRoot = await makeWorkspace();
    try {
      const { runtime, createSession, closeSession } = makeRuntime();
      const session = await createGondolinBackend({ runtime }).createSession({
        image: "image",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
      });

      await session.close();
      await session.close();
      expect(closeSession).toHaveBeenCalledTimes(1);
      expect(() => session.vfs.read({ operation: "read", path: "src/index.ts" })).toThrowError(
        expect.objectContaining({ code: "closed" }),
      );
      expect(() => session.network.request({ protocol: "https", domain: "api.example.com" }, 0)).toThrowError(
        expect.objectContaining({ code: "stale-generation" }),
      );
      expect(createSession).toHaveBeenCalledTimes(1);
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it("does not invoke runtime close twice when synchronous close fails", async () => {
    const workspaceRoot = await makeWorkspace();
    try {
      const closeSession = vi.fn(() => {
        throw new Error("close failed");
      });
      const runtime: GondolinRuntime = {
        createSession: vi.fn(async () => ({ close: closeSession })),
      };
      const session = await createGondolinBackend({ runtime }).createSession({
        image: "image",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
      });
      const first = session.close();
      const second = session.close();
      await expect(first).rejects.toThrow("close failed");
      await expect(second).rejects.toThrow("close failed");
      expect(closeSession).toHaveBeenCalledTimes(1);
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it("rejects an older session generation after a newer session is created", async () => {
    const workspaceRoot = await makeWorkspace();
    try {
      const { runtime } = makeRuntime();
      const backend = createGondolinBackend({ runtime });
      const first = await backend.createSession({ image: "image", workspaceRoot, policy: makePolicy(workspaceRoot) });
      await backend.createSession({ image: "image", workspaceRoot, policy: makePolicy(workspaceRoot) });
      expect(() => first.network.request({ protocol: "https", domain: "api.example.com" })).toThrowError(
        expect.objectContaining({ code: "stale-generation" }),
      );
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });

  it("delegates HTTP methods to the Phase 1A network policy and denies unknown domains and TCP", async () => {
    const workspaceRoot = await makeWorkspace();
    try {
      const { runtime } = makeRuntime();
      const session = await createGondolinBackend({ runtime }).createSession({
        image: "image",
        workspaceRoot,
        policy: makePolicy(workspaceRoot),
      });
      for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE"]) {
        expect(session.network.request({ protocol: "https", domain: "api.example.com", method })).toMatchObject({ decision: "allow" });
      }
      expect(session.network.request({ protocol: "https", domain: "unknown.example", method: "GET" })).toMatchObject({ decision: "deny" });
      expect(session.network.tcp({ domain: "api.example.com", port: 443 })).toMatchObject({ decision: "deny" });
      expect(session.network.tcp()).toMatchObject({ decision: "deny" });
      expect(session.network.tcp(null)).toMatchObject({ decision: "deny" });
    } finally {
      await rm(workspaceRoot, { recursive: true, force: true });
    }
  });
});
