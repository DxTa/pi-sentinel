import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { buildYoloAutoBashContext } from "./yolo-auto-bash-context.js";

const workspace = process.cwd();

describe("buildYoloAutoBashContext", () => {
  it("treats cd outside the workspace as non-local", () => {
    for (const command of ["cd .. && ls", "cd && ls", "cd ~ && ls", "cd - && ls", "ls; cd ../x; cat y"]) {
      expect(buildYoloAutoBashContext(command, [], workspace).workspaceLocal, command).toBe(false);
    }
    expect(buildYoloAutoBashContext("cd src && ls", [], workspace).workspaceLocal).toBe(true);
  });

  it("finds an escaping cd inside loops, groups, wrappers and after redirections", () => {
    for (const command of [
      "for d in a; do cd ..; done",
      "(cd .. && ls)",
      "{ cd ..; }",
      "bash -c 'cd .. && ls'",
      "cd .. 2>/dev/null && ls",
    ]) {
      expect(buildYoloAutoBashContext(command, [], workspace).workspaceLocal, command).toBe(false);
    }
    for (const command of [
      "bash -c 'cd src' && cd .. && ls",
      "(cd src) && cd .. && ls",
      "find . -exec cd .. {} + && ls",
    ]) {
      expect(buildYoloAutoBashContext(command, [], workspace).workspaceLocal, command).toBe(false);
    }
    for (const command of ["(cd src && ls)", "cd src && cd .. && ls", "for d in a; do ls; done", "cd src 2>/dev/null && ls", "python3 -c 'print(1)'"]) {
      expect(buildYoloAutoBashContext(command, [], workspace).workspaceLocal, command).toBe(true);
    }
  });

  it("fails closed when quoted line continuations hide an escaping cd", () => {
    const command = String.raw`cd && cat README.md && echo "a\
b"`;
    expect(buildYoloAutoBashContext(command, [], workspace).workspaceLocal).toBe(false);
  });

  it("treats output discard devices as workspace-neutral", () => {
    const result = buildYoloAutoBashContext("cd src 2>/dev/null && ls", ["/dev/null"], workspace);

    expect(result.workspaceLocal).toBe(true);
    expect(result.hardRuleHit).toBe(false);
  });

  it("keeps workspace-relative paths and commands eligible", () => {
    const result = buildYoloAutoBashContext("cat src/index.ts", ["src/index.ts"], workspace);

    expect(result).toEqual({
      command: "cat src/index.ts",
      workspaceLocal: true,
      hardRuleHit: false,
      units: ["cat src/index.ts"],
      opaque: false,
    });
  });

  it("redacts absolute workspace paths to relative paths", () => {
    const absolutePath = join(workspace, "src/index.ts");
    const result = buildYoloAutoBashContext("cat " + absolutePath, [absolutePath], workspace);

    expect(result).toMatchObject({
      command: "cat src/index.ts",
      workspaceLocal: true,
      hardRuleHit: false,
      units: ["cat src/index.ts"],
      opaque: false,
    });
    expect(result.command).not.toContain(workspace);
  });

  it("marks sensitive paths as hard rules and redacts them", () => {
    const result = buildYoloAutoBashContext("cat /etc/hosts", ["/etc/hosts"], workspace);

    expect(result).toMatchObject({ command: "cat <sensitive-path>", workspaceLocal: false, hardRuleHit: true });
    expect(result.command).not.toContain("/etc/hosts");
  });

  it("rejects unclassified absolute paths and redacts them", () => {
    const result = buildYoloAutoBashContext("printf /etc/hosts", [], workspace);

    expect(result).toMatchObject({ command: "printf <sensitive-path>", workspaceLocal: false, hardRuleHit: true });
  });

  it("rejects dynamic and external path operands", () => {
    const dynamic = buildYoloAutoBashContext("cat $HOME/.ssh/id_rsa", ["$HOME/.ssh/id_rsa"], workspace);
    const external = buildYoloAutoBashContext("cat ../outside.txt", ["../outside.txt"], workspace);

    expect(dynamic).toMatchObject({ command: "cat <sensitive-path>", workspaceLocal: false, hardRuleHit: true });
    expect(external).toMatchObject({ command: "cat <external-path>", workspaceLocal: false, hardRuleHit: false });
  });

  it("keeps recognized network targets out of classifier eligibility", () => {
    const result = buildYoloAutoBashContext("curl https://example.com/data", [], workspace);

    expect(result.workspaceLocal).toBe(false);
  });

  it("returns each inner command redacted like the whole command", () => {
    const result = buildYoloAutoBashContext("ls ../outside && for f in a; do cat src/a.ts; done", ["../outside", "src/a.ts"], workspace);

    expect(result.units).toEqual(["ls <external-path>", "cat src/a.ts"]);
    expect(result.opaque).toBe(false);
  });

  it("marks unreadable commands opaque and gives them no units when they cannot be split", () => {
    expect(buildYoloAutoBashContext('ls && eval "$x"', [], workspace)).toMatchObject({ units: ["ls", 'eval "$x"'], opaque: true });
    expect(buildYoloAutoBashContext('echo "$(id)"', [], workspace)).toMatchObject({ units: [], opaque: true });
  });
});
