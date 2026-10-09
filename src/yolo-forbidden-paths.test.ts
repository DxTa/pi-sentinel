import { mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { isForbiddenWritePath } from "./yolo-forbidden-paths";

const HOME = "/Users/alice";

describe("isForbiddenWritePath", () => {
  it.each([
    "/etc/hosts",
    "/etc",
    "/System/Library/x",
    "/Library/LaunchDaemons/a.plist",
    "/usr/lib/x",
    "/usr/bin/tool",
    "/bin/sh",
    "/sbin/mount",
    "/private/etc/hosts",
    "/var/db/x",
    "/private/var/db/x",
    "/Users/alice/.ssh/authorized_keys",
    "/Users/alice/.aws/credentials",
    "/Users/alice/.gnupg/pubring.kbx",
    "/work/../etc/hosts",
  ])("forbids %s", (path) => {
    expect(isForbiddenWritePath(path, HOME)).toBe(true);
  });

  it.each([
    "/usr/local/bin/tool",
    "/tmp/x",
    "/private/tmp/x",
    "/var/folders/ab/cd/T/x",
    "/private/var/folders/ab/cd/T/x",
    "/var/tmp/x",
    "/Users/alice/Library/Caches/pip/x",
    "/Users/alice/dev/repo/src/a.ts",
    "/Users/alice/.sshx/file",
    "/Users/alice/.config/app",
    "/opt/homebrew/bin/x",
    "/etcetera/x",
  ])("allows %s", (path) => {
    expect(isForbiddenWritePath(path, HOME)).toBe(false);
  });

  it("resolves a symlink before the .. that follows it", () => {
    const dir = mkdtempSync(join(tmpdir(), "forbidden-"));
    symlinkSync("/etc", join(dir, "link"));
    expect(isForbiddenWritePath(`${dir}/link/../etc/hosts`, HOME)).toBe(true);
    expect(isForbiddenWritePath(`${dir}/link/../elsewhere`, HOME)).toBe(false);
  });

  it("follows a symlink into a forbidden root", () => {
    const dir = mkdtempSync(join(tmpdir(), "forbidden-"));
    symlinkSync("/etc", join(dir, "link"));
    expect(isForbiddenWritePath(join(dir, "link", "hosts"), HOME)).toBe(true);
  });
});
