import { mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { SandboxPolicyManager } from "./policy-manager.js";

const tempPaths: string[] = [];

function makeManager(): SandboxPolicyManager {
  return new SandboxPolicyManager({ enabled: true, backend: "srt", profiles: {}, defaultProfile: "online-dev" });
}

function makeOfflineManager(): SandboxPolicyManager {
  return new SandboxPolicyManager({
    enabled: true,
    backend: "srt",
    profiles: {
      "offline-dev": {
        network: false,
        env: { allow: [], deny: [] },
        maskedPaths: [],
      },
    },
    defaultProfile: "offline-dev",
  });
}

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("SandboxPolicyManager grants", () => {
  it("rejects protected and broad path grants", () => {
    const manager = makeManager();
    try {
      expect(() => manager.grantPath(join(homedir(), ".env"), "ro")).not.toThrow();
      expect(() => manager.grantPath(join(homedir(), ".env"), "rw")).toThrow(/protected credential/i);
      expect(() => manager.grantPath(homedir(), "ro")).toThrow(/sensitive|broad/i);
      expect(() => manager.grantPath("/", "rw")).toThrow(/sensitive|broad/i);
      expect(() => manager.grantPath("/tmp", "ro")).toThrow(/sensitive|broad/i);
      expect(() => manager.grantPath("/var", "ro")).toThrow(/sensitive|broad/i);
    } finally {
      manager.destroy();
    }
  });

  it("allows Unix socket path grants", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-policy-socket-"));
    tempPaths.push(root);
    const socketPath = join(root, "docker.sock");
    const server = createServer();
    try {
      await new Promise<void>((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(socketPath, resolveListen);
      });
      const manager = makeManager();
      try {
        expect(() => manager.grantPath(socketPath, "ro")).not.toThrow();
      } finally {
        manager.destroy();
      }
    } finally {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    }
  });

  it("applies safe path grants only in their project scope", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-policy-grant-"));
    const otherRoot = await mkdtemp(join(tmpdir(), "pi-policy-other-"));
    tempPaths.push(root, otherRoot);
    const manager = makeManager();
    try {
      const canonicalRoot = await realpath(root);
      const grant = manager.grantPath(root, "rw", { projectRoot: root });
      expect(grant.value).toBe(canonicalRoot);
      expect(manager.resolveProfile("touch file", root, root).profile.rwBinds).toContain(canonicalRoot);
      expect(manager.resolveProfile("touch file", otherRoot, otherRoot).profile.rwBinds).not.toContain(canonicalRoot);
      expect(manager.revokeGrant(grant.id)).toBe(true);
      expect(manager.resolveProfile("touch file", root, root).profile.rwBinds).not.toContain(canonicalRoot);
    } finally {
      manager.destroy();
    }
  });

  it("requires network access for an explicit target in an offline profile", () => {
    const manager = makeOfflineManager();
    try {
      expect(manager.resolveProfile("curl https://example.com", "/repo")).toMatchObject({
        canExecute: false,
        requiredChanges: {
          type: "network",
          values: ["example.com"],
        },
      });
    } finally {
      manager.destroy();
    }
  });

  it("does not require generic network access without an explicit target", () => {
    const manager = makeOfflineManager();
    try {
      expect(manager.resolveProfile("npm install package", "/repo")).toMatchObject({
        canExecute: true,
        requiredChanges: undefined,
      });
    } finally {
      manager.destroy();
    }
  });

  it("clears network requirement after an applicable grant", () => {
    const manager = makeOfflineManager();
    try {
      manager.grantNetwork(["example.com"], { projectRoot: "/repo" });
      expect(manager.resolveProfile("curl https://example.com", "/repo", "/repo")).toMatchObject({
        canExecute: true,
        profile: { network: true },
        requiredChanges: undefined,
      });
    } finally {
      manager.destroy();
    }
  });

  it("supports invocation-only network approval without storing a grant", () => {
    const manager = makeOfflineManager();
    try {
      expect(manager.resolveProfile("curl https://example.com", "/repo", "/repo", { network: true })).toMatchObject({
        canExecute: true,
        profile: { network: true },
      });
      expect(manager.resolveProfile("curl https://example.com", "/repo", "/repo").canExecute).toBe(false);
    } finally {
      manager.destroy();
    }
  });

  it("preserves custom profile restrictions when network access is granted", () => {
    const manager = new SandboxPolicyManager({
      enabled: true,
      backend: "srt",
      profiles: {
        "offline-custom": {
          network: false,
          roBinds: ["/offline-only"],
          rwBinds: [],
          env: { allow: [], deny: ["SECRET"] },
          maskedPaths: ["offline-secret"],
        },
        "online-dev": {
          network: true,
          roBinds: ["/online-only"],
          rwBinds: [],
          env: { allow: [], deny: [] },
          maskedPaths: [],
        },
      },
      defaultProfile: "offline-custom",
    });
    try {
      manager.grantNetwork(["example.com"], { projectRoot: "/repo" });
      const profile = manager.resolveProfile("curl https://example.com", "/repo", "/repo").profile;

      expect(profile.network).toBe(true);
      expect(profile.roBinds).toEqual(["/offline-only"]);
      expect(profile.env.deny).toEqual(["SECRET"]);
      expect(profile.maskedPaths).toContain("offline-secret");
      expect(profile.roBinds).not.toContain("/online-only");
    } finally {
      manager.destroy();
    }
  });

  it("pins approved path grants to their canonical target", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-policy-symlink-"));
    tempPaths.push(root);
    const target = join(root, "target.txt");
    const replacement = join(root, "replacement.txt");
    const link = join(root, "approved.txt");
    await writeFile(target, "target");
    await writeFile(replacement, "replacement");
    await symlink(target, link);
    const manager = makeManager();
    try {
      const grant = manager.grantPath(link, "ro", { projectRoot: root });
      await rm(link);
      await symlink(replacement, link);

      const canonicalTarget = await realpath(target);
      expect(grant.value).toBe(canonicalTarget);
      expect(manager.resolveProfile("cat approved.txt", root, root).profile.roBinds).toContain(canonicalTarget);
      expect(manager.resolveProfile("cat approved.txt", root, root).profile.roBinds).not.toContain(await realpath(replacement));
    } finally {
      manager.destroy();
    }
  });

  it("applies path approval only to current invocation", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-policy-invocation-"));
    tempPaths.push(root);
    const manager = makeOfflineManager();
    try {
      const resolved = manager.resolveProfile("cat file", root, root, {
        pathGrants: [{ path: root, mode: "ro" }],
      });

      expect(resolved.profile.roBinds).toContain(root);
      expect(manager.listGrants()).toEqual([]);
      expect(manager.resolveProfile("cat file", root, root).profile.roBinds).not.toContain(root);
    } finally {
      manager.destroy();
    }
  });

  it("clears in-memory grants at session end", () => {
    const manager = makeOfflineManager();
    try {
      manager.grantNetwork(["example.com"], { projectRoot: "/repo" });
      expect(manager.listGrants()).toHaveLength(1);

      manager.clearGrants();

      expect(manager.listGrants()).toEqual([]);
      expect(manager.getCachedDomainVerdict("example.com")).toBeUndefined();
      expect(manager.resolveProfile("curl https://example.com", "/repo", "/repo").canExecute).toBe(false);
    } finally {
      manager.destroy();
    }
  });

  it("expires temporary grants", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-policy-expiry-"));
    tempPaths.push(root);
    const manager = makeManager();
    try {
      const grant = manager.grantPath(root, "ro", { duration: 1 });
      expect(manager.listGrants()).toContainEqual(grant);
      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(manager.listGrants()).not.toContainEqual(grant);
    } finally {
      manager.destroy();
    }
  });
});
