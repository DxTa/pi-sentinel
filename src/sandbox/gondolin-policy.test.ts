import { chmod, mkdir, mkdtemp, realpath, symlink, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  decideGondolinNetworkAccess,
  decideGondolinVfsAccess,
  normalizeGondolinPath,
} from "./gondolin-policy.js";

const workspaceRoot = "/workspace/project";

describe("normalizeGondolinPath", () => {
  it("normalizes workspace-relative and absolute paths without traversal", () => {
    expect(normalizeGondolinPath("src/../README.md", workspaceRoot)).toBe(
      "/workspace/project/README.md",
    );
    expect(normalizeGondolinPath("/workspace/project/src/index.ts", workspaceRoot)).toBe(
      "/workspace/project/src/index.ts",
    );
    expect(normalizeGondolinPath("../../etc/passwd", workspaceRoot)).toBeNull();
    expect(normalizeGondolinPath("/etc/passwd", workspaceRoot)).toBeNull();
  });

  it("resolves symlinked directories before checking containment", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-policy-"));
    const outside = await mkdtemp(join(tmpdir(), "gondolin-outside-"));
    try {
      await symlink(outside, join(root, "link"));
      expect(normalizeGondolinPath("link/secret.txt", root)).toBeNull();
    } finally {
      await Promise.all([
        rm(root, { recursive: true, force: true }),
        rm(outside, { recursive: true, force: true }),
      ]);
    }
  });

  it("resolves an absolute path through a symlinked workspace root", async () => {
    const realRoot = await mkdtemp(join(tmpdir(), "gondolin-policy-real-"));
    const rootAlias = `${realRoot}-alias`;
    try {
      await symlink(realRoot, rootAlias);
      expect(normalizeGondolinPath(`${rootAlias}/src/index.ts`, rootAlias)).toBe(
        `${await realpath(realRoot)}/src/index.ts`,
      );
    } finally {
      await Promise.all([
        rm(rootAlias, { force: true }),
        rm(realRoot, { recursive: true, force: true }),
      ]);
    }
  });

  it("denies dangling symlinks instead of using lexical containment", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-policy-dangling-"));
    const missingTarget = await mkdtemp(join(tmpdir(), "gondolin-policy-target-"));
    await rm(missingTarget, { recursive: true, force: true });
    try {
      await symlink(missingTarget, join(root, "dangling"));
      expect(normalizeGondolinPath("dangling", root)).toBeNull();
      expect(
        decideGondolinVfsAccess(
          { workspaceRoot: root },
          { operation: "read", path: "dangling" },
        ),
      ).toMatchObject({ decision: "deny" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("denies paths under unreadable ancestors", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-policy-unreadable-"));
    const blocked = join(root, "blocked");
    await mkdir(blocked);
    try {
      await chmod(blocked, 0o000);
      expect(normalizeGondolinPath("blocked/secret", root)).toBeNull();
    } finally {
      await chmod(blocked, 0o700);
      await rm(root, { recursive: true, force: true });
    }
  });

  it("fails closed for malformed path inputs", () => {
    expect(normalizeGondolinPath(undefined as never, workspaceRoot)).toBeNull();
    expect(normalizeGondolinPath("file", undefined as never)).toBeNull();
    expect(normalizeGondolinPath("file\u0000name", workspaceRoot)).toBeNull();
  });
});

describe("decideGondolinVfsAccess", () => {
  const policy = {
    workspaceRoot,
    sensitivePaths: ["**/.env", "secrets/**"],
  };

  it("returns the selected placeholder decision for sensitive reads", () => {
    expect(
      decideGondolinVfsAccess(policy, { operation: "read", path: ".env" }),
    ).toMatchObject({ decision: "placeholder", path: "/workspace/project/.env" });
    expect(
      decideGondolinVfsAccess(
        { ...policy, sensitiveReadDecision: "deny" },
        { operation: "read", path: ".env" },
      ),
    ).toMatchObject({ decision: "deny" });
  });

  it("masks common tool credential paths by default", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-policy-default-secrets-"));
    try {
      for (const path of [".env.local", ".config/gh/hosts.yml", ".cargo/credentials.toml", "cache/auth-token.json"]) {
        expect(decideGondolinVfsAccess({ workspaceRoot: root }, { operation: "read", path })).toMatchObject({
          decision: "placeholder",
        });
      }
      expect(decideGondolinVfsAccess({ workspaceRoot: root }, { operation: "read", path: "src/auth-handler.ts" })).toMatchObject({
        decision: "allow",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps host-managed Gondolin metadata readable but not writable", () => {
    const policy = { workspaceRoot: "/workspace", protectedPaths: [".pi", ".pi/gondolin", ".pi/gondolin/**"] };
    expect(decideGondolinVfsAccess(policy, { operation: "read", path: "/workspace/.pi/gondolin/image-lock.json" }).decision).toBe("allow");
    for (const path of ["/workspace/.pi", "/workspace/.pi/gondolin", "/workspace/.pi/gondolin/image-lock.json"]) {
      expect(decideGondolinVfsAccess(policy, { operation: "write", path })).toMatchObject({ decision: "deny" });
    }
  });

  it("allows ordinary workspace mutations but denies sensitive and unsupported operations", () => {
    expect(
      decideGondolinVfsAccess(policy, { operation: "read", path: "src/index.ts" }),
    ).toMatchObject({ decision: "allow" });
    for (const operation of ["write", "open", "mkdir", "rmdir", "unlink", "rename"]) {
      expect(
        decideGondolinVfsAccess(policy, { operation, path: "src/index.ts" }),
      ).toMatchObject({ decision: "allow" });
    }
    expect(
      decideGondolinVfsAccess(policy, { operation: "write", path: ".env" }),
    ).toMatchObject({ decision: "deny" });
    for (const operation of ["symlink", "chmod", "unknown"]) {
      expect(
        decideGondolinVfsAccess(policy, { operation, path: "src/index.ts" }),
      ).toMatchObject({ decision: "deny" });
    }
  });

  it("denies symlink targets outside the workspace and sensitive targets inside it", () => {
    expect(
      decideGondolinVfsAccess(policy, {
        operation: "read",
        path: "link-to-secret",
        resolvedTargetPath: "/etc/passwd",
      }),
    ).toMatchObject({ decision: "deny" });
    expect(
      decideGondolinVfsAccess(policy, {
        operation: "read",
        path: "ordinary-link",
        resolvedTargetPath: "/workspace/project/secrets/token",
      }),
    ).toMatchObject({ decision: "placeholder" });
  });

  it("masks a sensitive symlink alias even when target is ordinary", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-policy-sensitive-link-"));
    try {
      await writeFile(join(root, "payload"), "ordinary");
      await symlink(join(root, "payload"), join(root, ".env"));
      expect(
        decideGondolinVfsAccess(
          { workspaceRoot: root, sensitivePaths: ["**/.env"] },
          { operation: "read", path: ".env" },
        ),
      ).toMatchObject({ decision: "placeholder" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("matches absolute sensitive patterns when the workspace root is a symlink", async () => {
    const realRoot = await mkdtemp(join(tmpdir(), "gondolin-policy-pattern-real-"));
    const rootAlias = `${realRoot}-alias`;
    try {
      await symlink(realRoot, rootAlias);
      expect(
        decideGondolinVfsAccess(
          { workspaceRoot: rootAlias, sensitivePaths: [`${rootAlias}/.env`] },
          { operation: "read", path: ".env" },
        ),
      ).toMatchObject({ decision: "placeholder" });
    } finally {
      await Promise.all([
        rm(rootAlias, { force: true }),
        rm(realRoot, { recursive: true, force: true }),
      ]);
    }
  });

  it("denies invalid sensitive-path policies instead of ignoring unsafe patterns", () => {
    for (const sensitivePath of ["../outside/**", "secrets\u0000/**"]) {
      expect(
        decideGondolinVfsAccess(
          { workspaceRoot, sensitivePaths: [sensitivePath] },
          { operation: "read", path: "src/index.ts" },
        ),
      ).toMatchObject({ decision: "deny" });
    }
  });
});

describe("decideGondolinNetworkAccess", () => {
  const policy = { allowedDomains: ["api.example.com", "*.trusted.test"] };

  it("denies explicitly denied domains before allowlist matching", () => {
    expect(
      decideGondolinNetworkAccess(
        { allowedDomains: ["*"], deniedDomains: ["*.blocked.test"] },
        { protocol: "https", domain: "api.blocked.test", method: "GET" },
      ),
    ).toMatchObject({ decision: "deny", domain: "api.blocked.test" });
  });

  it("allows every HTTP method only for allowlisted domains", () => {
    for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      expect(
        decideGondolinNetworkAccess(policy, {
          protocol: "https",
          method,
          domain: "api.example.com",
        }),
      ).toMatchObject({ decision: "allow", domain: "api.example.com" });
    }
    expect(
      decideGondolinNetworkAccess(policy, {
        protocol: "https",
        method: "GET",
        domain: "unknown.example",
      }),
    ).toMatchObject({ decision: "deny" });
  });

  it("blocks generic TCP even when a domain is allowlisted", () => {
    expect(
      decideGondolinNetworkAccess(policy, {
        protocol: "tcp",
        domain: "api.example.com",
      }),
    ).toMatchObject({ decision: "deny" });
  });

  it("fails closed for malformed requests and policies", () => {
    expect(
      decideGondolinNetworkAccess(policy, {
        protocol: undefined as never,
        domain: "api.example.com",
      }),
    ).toMatchObject({ decision: "deny" });
    expect(
      decideGondolinNetworkAccess({ allowedDomains: undefined as never }, {
        protocol: "https",
        domain: "api.example.com",
      }),
    ).toMatchObject({ decision: "deny" });
    expect(
      decideGondolinNetworkAccess(
        { allowedDomains: ["api.example.com", "https://"] },
        { protocol: "https", domain: "api.example.com" },
      ),
    ).toMatchObject({ decision: "deny" });
    for (const domain of [".", "..", "...", "a..b"]) {
      expect(
        decideGondolinNetworkAccess(
          { allowedDomains: ["*"] },
          { protocol: "https", domain },
        ),
      ).toMatchObject({ decision: "deny", domain: null });
    }
    expect(
      decideGondolinNetworkAccess(
        { allowedDomains: ["*."] },
        { protocol: "https", domain: "unknown.example" },
      ),
    ).toMatchObject({ decision: "deny" });
  });
});
