import { mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { forbiddenWriteTarget } from "./yolo-forbidden-writes";

const HOME = "/Users/alice";
const CWD = "/work/repo";
const bash = (command: string) => forbiddenWriteTarget("bash", { command }, CWD, HOME);

describe("forbiddenWriteTarget: file tools", () => {
  it("returns the resolved path of a write or edit into a forbidden root", () => {
    expect(forbiddenWriteTarget("write", { path: "/etc/hosts" }, CWD, HOME)).toBe("/etc/hosts");
    expect(forbiddenWriteTarget("edit", { path: "../../etc/hosts" }, CWD, HOME)).toBe("/etc/hosts");
    expect(forbiddenWriteTarget("write", { path: "/Users/alice/.ssh/config" }, CWD, HOME)).toBe("/Users/alice/.ssh/config");
  });

  it("allows ordinary paths and every read", () => {
    expect(forbiddenWriteTarget("write", { path: "/tmp/x" }, CWD, HOME)).toBeNull();
    expect(forbiddenWriteTarget("write", { path: "src/a.ts" }, CWD, HOME)).toBeNull();
    expect(forbiddenWriteTarget("read", { path: "/etc/hosts" }, CWD, HOME)).toBeNull();
    expect(forbiddenWriteTarget("ls", { path: "/etc" }, CWD, HOME)).toBeNull();
  });
});

describe("forbiddenWriteTarget: Bash", () => {
  it.each([
    ["echo x > /etc/hosts", "/etc/hosts"],
    ["echo x >> ~/.ssh/authorized_keys", "/Users/alice/.ssh/authorized_keys"],
    ["cat a 2> /etc/err", "/etc/err"],
    ["echo x &>/etc/out", "/etc/out"],
    ['echo x > "/etc/hosts"', "/etc/hosts"],
    ["echo x > $HOME/.aws/credentials", "/Users/alice/.aws/credentials"],
    ['echo "$(id)" > /etc/x', "/etc/x"],
    ["cp a.txt /etc/hosts", "/etc/hosts"],
    ["cp -r a b /usr/bin/", "/usr/bin"],
    ["cp -t /etc a b", "/etc"],
    ["mv a /usr/bin/x", "/usr/bin/x"],
    ["mv /etc/hosts ./h", "/etc/hosts"],
    ["ln -s a /usr/bin/x", "/usr/bin/x"],
    ["install -m 755 a /usr/bin/a", "/usr/bin/a"],
    ["echo x | tee /etc/hosts", "/etc/hosts"],
    ["sed -i 's/a/b/' /etc/hosts", "/etc/hosts"],
    ["sed -i -e 's/a/b/' /etc/hosts", "/etc/hosts"],
    ["sed -i.bak -e's/a/b/' /etc/hosts", "/etc/hosts"],
    ["sed -i --expression=s/a/b/ /etc/hosts", "/etc/hosts"],
    ["sed -i -fscript.sed /etc/hosts", "/etc/hosts"],
    ["sed -i --file script.sed /etc/hosts", "/etc/hosts"],
    ["dd if=/dev/zero of=/etc/x", "/etc/x"],
    ["curl -o /etc/x http://example.test", "/etc/x"],
    ["wget -O /usr/bin/x http://example.test", "/usr/bin/x"],
    ["touch /usr/bin/x", "/usr/bin/x"],
    ["mkdir -p ~/.aws", "/Users/alice/.aws"],
    ["chmod 600 ~/.ssh/id_rsa", "/Users/alice/.ssh/id_rsa"],
    ["rm -rf /etc/x", "/etc/x"],
    ["cd /etc && touch hosts", "/etc/hosts"],
    ["cd /etc && echo x > hosts", "/etc/hosts"],
    ["for f in a; do cp $f /etc/x; done", "/etc/x"],
    ["bash -c 'echo x > /etc/hosts'", "/etc/hosts"],
    ["ls | xargs rm /etc/x", "/etc/x"],
    ["sudo tee /etc/hosts", "/etc/hosts"],
  ])("blocks %s", (command, target) => {
    expect(bash(command)).toBe(target);
  });

  it.each([
    "cat /etc/hosts",
    "ls /usr/bin",
    "grep x /etc/hosts",
    "cp /etc/hosts ./h",
    "sed 's/a/b/' /etc/hosts",
    "sed -i '/usr/d' notes.txt",
    "dd if=/etc/hosts of=./h",
    'echo "a > /etc/hosts"',
    "echo x > /dev/null",
    "ls 2>&1",
    "cd /usr/local && touch x",
    "echo x > /tmp/x",
    "touch ~/Library/Caches/x",
    "(cd /etc) && ls",
    "git status",
    "python3 -c \"open('/etc/x','w')\"",
    'eval "echo x > /etc/y"',
  ])("lets %s through", (command) => {
    expect(bash(command)).toBeNull();
  });

  it("does not let a symlink hide a forbidden target behind ..", () => {
    const dir = mkdtempSync(join(tmpdir(), "forbidden-writes-"));
    symlinkSync("/etc", join(dir, "link"));
    expect(forbiddenWriteTarget("bash", { command: "echo x > link/../etc/hosts" }, dir, HOME)).not.toBeNull();
    expect(forbiddenWriteTarget("write", { path: "link/../etc/hosts" }, dir, HOME)).not.toBeNull();
  });

  it("still checks relative targets from the start directory after a child-shell cd", () => {
    expect(bash("(cd /etc) && touch ../../etc/x")).toBe("/etc/x");
  });
});
