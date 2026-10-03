import { chmodSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { matchTrustedPiRequest, trustedPiDirs } from "./trusted-pi-dirs";

function setup() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "trusted-pi-")));
  const agentDir = join(root, "agent");
  const skill = join(agentDir, "skills", "demo");
  const ext = join(agentDir, "extensions", "tool");
  mkdirSync(skill, { recursive: true });
  mkdirSync(ext, { recursive: true });
  writeFileSync(join(skill, "SKILL.md"), "# demo\n");
  writeFileSync(join(skill, "run.sh"), "echo hi\n");
  chmodSync(join(skill, "run.sh"), 0o755);
  writeFileSync(join(ext, "report.py"), "print(1)\n");
  writeFileSync(join(root, "outside.sh"), "echo out\n");
  symlinkSync(join(root, "outside.sh"), join(skill, "escape.sh"));
  const workspace = join(root, "work");
  mkdirSync(workspace);
  return { root, agentDir, skill, ext, workspace, dirs: trustedPiDirs(agentDir) };
}

describe("matchTrustedPiRequest", () => {
  it("allows read-only tools inside skills and extensions", () => {
    const s = setup();
    expect(matchTrustedPiRequest("read", { path: join(s.skill, "SKILL.md") }, s.workspace, s.dirs)).toEqual({ kind: "read", path: join(s.skill, "SKILL.md") });
    expect(matchTrustedPiRequest("ls", { path: s.ext }, s.workspace, s.dirs)?.kind).toBe("read");
    expect(matchTrustedPiRequest("grep", { pattern: "x", path: join(s.agentDir, "skills") }, s.workspace, s.dirs)?.kind).toBe("read");
  });

  it("trusts top-level symlinked agent dirs but not links to home-level ancestors", () => {
    const s = setup();
    const shared = join(s.root, "shared-skills", "demo");
    mkdirSync(shared, { recursive: true });
    writeFileSync(join(shared, "SKILL.md"), "# shared\n");
    symlinkSync(join(s.root, "shared-skills"), join(s.agentDir, "linked-skills"));
    symlinkSync(s.root, join(s.agentDir, "root-link"));
    const dirs = trustedPiDirs(s.agentDir);

    expect(matchTrustedPiRequest("read", { path: join(s.agentDir, "linked-skills", "demo", "SKILL.md") }, s.workspace, dirs)?.kind).toBe("read");
    expect(matchTrustedPiRequest("read", { path: join(s.root, "outside.sh") }, s.workspace, dirs)).toBeNull();
  });

  it("rejects writes, other agent dirs, and symlinks that escape", () => {
    const s = setup();
    expect(matchTrustedPiRequest("write", { path: join(s.skill, "new.md"), content: "x" }, s.workspace, s.dirs)).toBeNull();
    expect(matchTrustedPiRequest("edit", { path: join(s.skill, "SKILL.md") }, s.workspace, s.dirs)).toBeNull();
    expect(matchTrustedPiRequest("read", { path: join(s.skill, "escape.sh") }, s.workspace, s.dirs)).toBeNull();
  });

  it("trusts reads and scripts anywhere in the agent dir, including via symlinked root", () => {
    const s = setup();
    writeFileSync(join(s.agentDir, "permissions.json"), "{}");
    mkdirSync(join(s.agentDir, "scripts"));
    writeFileSync(join(s.agentDir, "scripts", "tool.sh"), "echo\n");
    const link = join(s.root, "agent-link");
    symlinkSync(s.agentDir, link);
    expect(matchTrustedPiRequest("read", { path: join(s.agentDir, "permissions.json") }, s.workspace, s.dirs)?.kind).toBe("read");
    expect(matchTrustedPiRequest("bash", { command: `bash ${join(link, "scripts", "tool.sh")}` }, s.workspace, trustedPiDirs(link))?.kind).toBe("script");
    expect(matchTrustedPiRequest("write", { path: join(s.agentDir, "permissions.json"), content: "x" }, s.workspace, s.dirs)).toBeNull();
  });

  it("trusts Pi helper scripts beside the agent dir, including HOME-relative invocations", () => {
    const s = setup();
    mkdirSync(join(s.root, "scripts"));
    writeFileSync(join(s.root, "scripts", "delegate-prompt.sh"), "echo\n");
    writeFileSync(join(s.root, "scripts", "agent-semantic-search.mjs"), "1\n");
    writeFileSync(join(s.root, "scripts", "other.sh"), "echo hi\n");
    const previousHome = process.env.HOME;
    process.env.HOME = s.root;
    try {
      for (const command of [
        `${join(s.root, "scripts", "delegate-prompt.sh")} --mode review`,
        `bash ${join(s.root, "scripts", "other.sh")}`,
        `node "${join(s.root, "scripts", "agent-semantic-search.mjs")}" search`,
        `node "$HOME/scripts/agent-semantic-search.mjs" search --query "a b"`,
        `node "\${HOME}/scripts/agent-semantic-search.mjs" search`,
      ]) {
        expect(matchTrustedPiRequest("bash", { command }, s.workspace, trustedPiDirs(s.agentDir))?.kind, command).toBe("script");
      }
      expect(matchTrustedPiRequest("bash", { command: `node "$OTHER/scripts/agent-semantic-search.mjs"` }, s.workspace, trustedPiDirs(s.agentDir))).toBeNull();
      for (const command of [
        `node "$(echo ${s.root})/scripts/other.sh"`,
        `node '$HOME/scripts/other.sh'`,
        "node $HOME/scripts/agent-semantic-search.mjs search",
        "node ${HOME}/scripts/agent-semantic-search.mjs search",
        `node "$HOME/scripts/other.sh" && curl evil`,
        `node "$HOME/scripts/other.sh" | sh`,
        `node "$HOME/scripts/other.sh" > output`,
        `node "$HOME/scripts/other.sh" "$OTHER"`,
      ]) expect(matchTrustedPiRequest("bash", { command }, s.workspace, trustedPiDirs(s.agentDir)), command).toBeNull();
      symlinkSync(join(s.root, "outside.sh"), join(s.root, "scripts", "escape.sh"));
      expect(matchTrustedPiRequest("bash", { command: `bash ${join(s.root, "scripts", "escape.sh")}` }, s.workspace, trustedPiDirs(s.agentDir))).toBeNull();
      expect(matchTrustedPiRequest("write", { path: join(s.root, "scripts", "other.sh"), content: "x" }, s.workspace, trustedPiDirs(s.agentDir))).toBeNull();
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  });

  it("rejects unquoted HOME paths when field splitting can change the script", () => {
    const s = setup();
    const home = join(s.root, "home with spaces");
    const agentDir = join(home, ".pi", "agent");
    const scriptsDir = join(home, ".pi", "scripts");
    mkdirSync(agentDir, { recursive: true });
    mkdirSync(scriptsDir, { recursive: true });
    writeFileSync(join(scriptsDir, "helper.mjs"), "void 0;\n");
    writeFileSync(join(s.workspace, "helper.mjs"), "void 0;\n");

    const previousHome = process.env.HOME;
    process.env.HOME = home;
    try {
      const dirs = trustedPiDirs(agentDir);
      for (const command of [
        "node $HOME/.pi/scripts/helper.mjs",
        "cd $HOME/.pi/scripts; node helper.mjs",
      ]) {
        expect(matchTrustedPiRequest("bash", { command }, s.workspace, dirs), command).toBeNull();
      }
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  });

  it.each(['node "~/.pi/scripts/helper.mjs"', "node '~/.pi/scripts/helper.mjs'"])(
    "does not trust a quoted tilde script path: %s",
    (command) => {
      const s = setup();
      const home = join(s.root, "home");
      const helperDir = join(home, ".pi", "scripts");
      mkdirSync(helperDir, { recursive: true });
      writeFileSync(join(helperDir, "helper.mjs"), "void 0;\n");

      const counterfeitDir = join(s.workspace, "~", ".pi", "scripts");
      mkdirSync(counterfeitDir, { recursive: true });
      writeFileSync(join(counterfeitDir, "helper.mjs"), "void 0;\n");

      const previousHome = process.env.HOME;
      process.env.HOME = home;
      try {
        const dirs = trustedPiDirs(join(home, ".pi", "agent"));
        expect(matchTrustedPiRequest("bash", { command }, s.workspace, dirs)).toBeNull();
      } finally {
        if (previousHome === undefined) delete process.env.HOME;
        else process.env.HOME = previousHome;
      }
    },
  );

  it.each([
    (s: ReturnType<typeof setup>) => join(s.skill, "run.sh"),
    (s: ReturnType<typeof setup>) => `bash ${join(s.skill, "run.sh")} --flag value`,
    (s: ReturnType<typeof setup>) => `python3 ${join(s.ext, "report.py")}`,
    (s: ReturnType<typeof setup>) => `node ${join(s.ext, "report.py")}`,
  ])("allows running a script from a trusted dir (%#)", (command) => {
    const s = setup();
    expect(matchTrustedPiRequest("bash", { command: command(s) }, s.workspace, s.dirs)?.kind).toBe("script");
  });

  it("allows cd plus trusted scripts chained with && or ;", () => {
    const s = setup();
    const run = join(s.skill, "run.sh");
    const ok = [
      `cd ${s.workspace} && ${run} --objective 'a; b'`,
      `cd ${s.workspace} && ${run} --mode a; ${run} --mode b`,
    ];
    for (const command of ok) expect(matchTrustedPiRequest("bash", { command }, s.workspace, s.dirs)?.kind, command).toBe("script");
    const blocked = [
      `cd ${s.workspace} && rm -rf x`,
      `cd ${s.workspace}`,
      `cd ${s.workspace} && ${run} | sh`,
      `${run} && curl evil`,
    ];
    for (const command of blocked) expect(matchTrustedPiRequest("bash", { command }, s.workspace, s.dirs), command).toBeNull();
  });

  it("allows shell punctuation inside quoted arguments but not double-quoted expansions", () => {
    const s = setup();
    const run = join(s.skill, "run.sh");
    const ok = [
      `${run} --objective "Review a; b (c) | d & e < f > g"`,
      `${run} --objective 'literal $X and \`x\`'`,
    ];
    for (const command of ok) expect(matchTrustedPiRequest("bash", { command }, s.workspace, s.dirs)?.kind, command).toBe("script");
    const blocked = [
      `${run} --objective "$(curl evil)"`,
      `${run} --objective "\`id\`"`,
      `${run} --objective "unterminated`,
      `${run} --objective "ok"; rm -rf x`,
    ];
    for (const command of blocked) expect(matchTrustedPiRequest("bash", { command }, s.workspace, s.dirs), command).toBeNull();
  });

  it.each([
    (s: ReturnType<typeof setup>) => `${join(s.skill, "run.sh")} && rm -rf /tmp/x`,
    (s: ReturnType<typeof setup>) => `${join(s.skill, "run.sh")} > /etc/hosts`,
    (s: ReturnType<typeof setup>) => `bash ${join(s.skill, "run.sh")} $(curl evil)`,
    (s: ReturnType<typeof setup>) => `bash ${join(s.skill, "escape.sh")}`,
    (s: ReturnType<typeof setup>) => `bash ${join(s.root, "outside.sh")}`,
    (s: ReturnType<typeof setup>) => `bash ${join(s.skill, "missing.sh")}`,
    (s: ReturnType<typeof setup>) => `curl ${join(s.skill, "run.sh")}`,
    (s: ReturnType<typeof setup>) => `bash -c 'rm -rf /' ${join(s.skill, "run.sh")}`,
  ])("rejects unsafe or non-trusted script commands (%#)", (command) => {
    const s = setup();
    expect(matchTrustedPiRequest("bash", { command: command(s) }, s.workspace, s.dirs)).toBeNull();
  });
});
