import { describe, expect, it, vi } from "vitest";

const { canonicalOverrides } = vi.hoisted(() => ({ canonicalOverrides: new Map<string, string>() }));
vi.mock("./sandbox/sandbox-visible-paths.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./sandbox/sandbox-visible-paths.js")>();
  return {
    ...actual,
    canonicalPath: (path: string) => canonicalOverrides.get(path) ?? actual.canonicalPath(path),
  };
});
import { isProtectedWriteTarget, isSensitivePath } from "./auto-mode-sensitive-paths.js";
import { canonicalPath } from "./sandbox/sandbox-visible-paths.js";

const HOME = "/Users/alice";

describe("isSensitivePath", () => {
  it.each([
    "/etc/hosts",
    "/System/Library/x",
    "/Library/Preferences/a.plist",
    "/usr/local/bin/tool",
    "/bin/sh",
    "/sbin/mount",
    "/private/var/db/x",
    "/Users/alice/Library/Keychains/login.keychain-db",
    "/etc",
  ])("flags system root %s", (p) => {
    expect(isSensitivePath(p, HOME)).toBe(true);
  });

  it.each([
    "/Users/alice/dev/app/src/index.ts",
    "/Users/alice/.ssh/config",
    "/etcetera/file",
    "/usrlocal",
    "/Users/alice/LibraryNotes/a.md",
  ])("does not flag %s", (p) => {
    expect(isSensitivePath(p, HOME)).toBe(false);
  });

  it("canonicalizes system-root aliases before matching", () => {
    const canonicalTmp = canonicalPath("/tmp");
    expect(isSensitivePath("/tmp/auto-mode-nonexistent", HOME)).toBe(
      canonicalTmp === "/private/tmp" || canonicalTmp.startsWith("/private/tmp/"),
    );
  });

  it("keeps protected lexical paths sensitive when a symlink resolves outside", () => {
    canonicalOverrides.set("/etc/symlink-out", "/Users/alice/project/target");
    try {
      expect(isSensitivePath("/etc/symlink-out", HOME)).toBe(true);
    } finally {
      canonicalOverrides.delete("/etc/symlink-out");
    }
  });

  it("matches Library paths through a canonicalized home alias", () => {
    canonicalOverrides.set("/Users/alice/Library", "/Volumes/home/alice/Library");
    canonicalOverrides.set("/Volumes/home/alice/Library/item", "/Volumes/home/alice/Library/item");
    try {
      expect(isSensitivePath("/Volumes/home/alice/Library/item", HOME)).toBe(true);
    } finally {
      canonicalOverrides.clear();
    }
  });

  it("resolves traversal before matching", () => {
    expect(isSensitivePath("/Users/alice/dev/../../../etc/passwd", HOME)).toBe(true);
  });
});

describe("isProtectedWriteTarget", () => {
  it.each(["/Users/alice/.ssh/authorized_keys", "/Users/alice/.aws/credentials", "/Users/alice/.zshrc", "/Users/alice/.bashrc", "/Users/alice/.zprofile", "/etc/hosts"])(
    "protects %s", (path) => expect(isProtectedWriteTarget(path, HOME)).toBe(true));
  it.each(["/Users/alice/Documents/a.txt", "/Users/alice/dev/app/.zshrc", "/Users/alice/dev/x.ts"])(
    "leaves %s writable", (path) => expect(isProtectedWriteTarget(path, HOME)).toBe(false));
});
