import { rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { PermissionCheckResult } from "../../types";
import { describeBashExternalDirectoryGate } from "./bash-external-directory";

const FALLBACK_ENV = "PI_PERMISSION_SYSTEM_DISABLE_TREE_SITTER";
const cwd = path.join("/tmp", "project");

afterEach(() => {
  delete process.env[FALLBACK_ENV];
});

function makeCheckResult(
  overrides: Partial<PermissionCheckResult> = {},
): PermissionCheckResult {
  return {
    toolName: "external_directory",
    state: "ask",
    source: "default",
    origin: "builtin",
    ...overrides,
  };
}

function expectDescriptor(
  result: Awaited<ReturnType<typeof describeBashExternalDirectoryGate>>,
) {
  expect(result).not.toBeNull();
  expect(result && !("action" in result)).toBe(true);
  if (!result || "action" in result) {
    throw new Error("Expected gate descriptor");
  }
  return result;
}

describe("describeBashExternalDirectoryGate", () => {
  it("checks explicit external-directory rules for interpreter-embedded credential paths", async () => {
    const credentialPath = path.join(homedir(), ".aws", "credentials");
    const checkedPaths: string[] = [];
    const result = await describeBashExternalDirectoryGate(
      {
        toolName: "bash",
        agentName: "worker",
        input: { command: `python3 -c "open('${credentialPath}').read()"` },
        toolCallId: "call-embedded-credential",
        cwd,
        sandboxed: true,
      },
      (_surface, input) => {
        const target = (input as { path?: string }).path;
        if (target === credentialPath) {
          checkedPaths.push(target);
          return makeCheckResult({ state: "deny", origin: "project" });
        }
        return makeCheckResult({ state: "allow", origin: "project" });
      },
      () => [],
    );

    expect(checkedPaths).toContain(credentialPath);
    expect(result).toMatchObject({
      preCheck: { state: "deny", origin: "project" },
      denialContext: { externalPaths: [credentialPath] },
    });
  });

  it("honors exact denies for parenthetical paths embedded in interpreter source", async () => {
    const credentialPath = path.join(homedir(), ".config", "gcloud", "settings(backup).json");
    const command = `python3 -c "print(open('${credentialPath}').read())"`;
    const checkedPaths: string[] = [];
    const result = await describeBashExternalDirectoryGate(
      {
        toolName: "bash",
        agentName: "worker",
        input: { command },
        toolCallId: "call-embedded-parenthetical-deny",
        cwd,
        sandboxed: true,
      },
      (_surface, input) => {
        const target = (input as { path?: string }).path;
        if (target) checkedPaths.push(target);
        return makeCheckResult({
          state: target === credentialPath ? "deny" : "ask",
          origin: target === credentialPath ? "project" : "builtin",
        });
      },
      () => [],
    );

    expect(checkedPaths).toContain(credentialPath);
    expect(result).toMatchObject({ preCheck: { state: "deny", origin: "project" } });
  });

  it("neither forces a prompt nor hard-blocks external writes in yolo mode", async () => {
    process.env[FALLBACK_ENV] = "1";

    const result = await describeBashExternalDirectoryGate(
      { toolName: "bash", agentName: "worker", input: { command: "touch /opt/shared/notes.txt" }, toolCallId: "call-yolo", cwd, mode: "yolo" },
      () => makeCheckResult(),
      () => [],
    );

    expect(result).not.toMatchObject({ preResolved: { state: "deny" } });
    expect((result as any)?.promptDetails?.forcePromptInYolo).toBeUndefined();
  });

  it("hard-blocks mutating commands outside workspace and temporary roots", async () => {
    process.env[FALLBACK_ENV] = "1";

    const result = await describeBashExternalDirectoryGate(
      {
        toolName: "bash",
        agentName: "worker",
        input: { command: "rm -rf /etc/passwd" },
        toolCallId: "call-hard-block",
        cwd,
      },
      () => makeCheckResult({ state: "allow", source: "special", origin: "project" }),
      () => [],
    );

    expect(result).toMatchObject({
      preResolved: { state: "deny" },
      denialContext: {
        kind: "bash_external_directory",
        externalPaths: ["/etc/passwd"],
      },
    });
  });

  it("does not treat absolute rm executable as mutation target", async () => {
    process.env[FALLBACK_ENV] = "1";

    const result = await describeBashExternalDirectoryGate(
      {
        toolName: "bash",
        agentName: "worker",
        input: { command: "/bin/rm -rf /tmp/pi-sentinel-safe" },
        toolCallId: "call-absolute-rm",
        cwd,
      },
      () => makeCheckResult(),
      () => [],
    );

    expect(result).not.toMatchObject({ preResolved: { state: "deny" } });
  });

  it.each(["/tmp/pi-sentinel-safe", "/private/tmp/pi-sentinel-safe"])(
    "does not hard-block mutating commands under %s",
    async (safePath) => {
      process.env[FALLBACK_ENV] = "1";

      const result = await describeBashExternalDirectoryGate(
        {
          toolName: "bash",
          agentName: "worker",
          input: { command: `rm -rf ${safePath}` },
          toolCallId: "call-safe-temp",
          cwd,
        },
        () => makeCheckResult(),
        () => [],
      );

      expect(result).not.toMatchObject({ preResolved: { state: "deny" } });
    },
  );
  it("does not force a prompt in yolo for read-only external bash commands", async () => {
    process.env[FALLBACK_ENV] = "1";

    const result = expectDescriptor(
      await describeBashExternalDirectoryGate(
        {
          toolName: "bash",
          agentName: "worker",
          input: { command: "cat ../secret.txt" },
          toolCallId: "call-read-only",
          cwd,
        },
        () => makeCheckResult(),
        () => [],
      ),
    );

    expect((result.promptDetails as any).forcePromptInYolo).toBeUndefined();
  });

  it("forces a prompt for mutating external bash commands outside yolo", async () => {
    process.env[FALLBACK_ENV] = "1";

    const result = expectDescriptor(
      await describeBashExternalDirectoryGate(
        {
          toolName: "bash",
          agentName: "worker",
          input: { command: "cp ../secret.txt ./copy.txt" },
          toolCallId: "call-copy",
          cwd,
        },
        () => makeCheckResult(),
        () => [],
      ),
    );

    expect((result.promptDetails as any).forcePromptInYolo).toBe(true);
  });

  it("forces a prompt for redirected read-only bash commands outside yolo", async () => {
    process.env[FALLBACK_ENV] = "1";

    const result = expectDescriptor(
      await describeBashExternalDirectoryGate(
        {
          toolName: "bash",
          agentName: "worker",
          input: { command: "cat ../secret.txt > ./copy.txt" },
          toolCallId: "call-redirect",
          cwd,
        },
        () => makeCheckResult(),
        () => [],
      ),
    );

    expect((result.promptDetails as any).forcePromptInYolo).toBe(true);
  });

  it("treats existing non-session external_directory allows as covered", async () => {
    process.env[FALLBACK_ENV] = "1";
    const externalPath = path.normalize(path.join("/tmp", "secret.txt"));

    const result = await describeBashExternalDirectoryGate(
      {
        toolName: "bash",
        agentName: "worker",
        input: { command: "cat ../secret.txt" },
        toolCallId: "call-covered",
        cwd,
      },
      (surface, input) => {
        const pathValue = (input as { path?: string }).path;
        if (surface === "external_directory" && pathValue === externalPath) {
          return makeCheckResult({
            state: "allow",
            source: "special",
            origin: "project",
          });
        }

        return makeCheckResult();
      },
      () => [],
    );

    expect(result).toMatchObject({ action: "allow" });
  });
});

describe("describeBashExternalDirectoryGate protected credential reads", () => {
  const context = (command: string, sandboxed = true) => ({
    toolName: "bash",
    agentName: null,
    input: { command },
    toolCallId: "call-protected",
    cwd,
    sandboxed,
  });

  it.each([
    "cat ~/.ssh/config",
    "cat ~/.config/gh/hosts.yml | head -5",
    "docker run --env-file ~/.aws/credentials alpine:latest",
    "docker run --env-file=~/.aws/credentials alpine:latest",
  ])("auto-allows %s", async (command) => {
    const result = await describeBashExternalDirectoryGate(context(command), () => makeCheckResult(), () => []);
    expect(result).toMatchObject({ action: "allow" });
  });

  it.each([
    "cat ~/.ssh/config > /tmp/out",
    "cp ~/.ssh/config /tmp/x",
    "cat ~/.ssh/config /etc/hosts",
  ])(
    "does not auto-allow %s",
    async (command) => {
      const result = await describeBashExternalDirectoryGate(context(command), () => makeCheckResult(), () => []);
      expect(result).not.toMatchObject({ action: "allow" });
    },
  );

  it("does not auto-allow protected paths outside SRT", async () => {
    const result = await describeBashExternalDirectoryGate(
      context("cat ~/.ssh/config", false),
      () => makeCheckResult(),
      () => [],
    );
    expect(result).not.toMatchObject({ action: "allow" });
  });

  it("does not bypass an explicit external-directory deny", async () => {
    const result = await describeBashExternalDirectoryGate(
      context("cat ~/.ssh/config"),
      () => makeCheckResult({ state: "deny", source: "special", origin: "project" }),
      () => [],
    );
    expect(result).not.toMatchObject({ action: "allow" });
  });
});

describe("describeBashExternalDirectoryGate clipboard temp files", () => {
  const context = (command: string) => ({
    toolName: "bash",
    agentName: null,
    input: { command },
    toolCallId: "call-clipboard",
    cwd,
  });

  it("auto-allows read-only Bash on a pi-clipboard file but not writes or mixed paths", async () => {
    const clipboardPath = path.join(tmpdir(), "pi-clipboard-11111111-2222-3333-4444-555555555555.png");
    writeFileSync(clipboardPath, "png");
    try {
      await expect(describeBashExternalDirectoryGate(context(`cat ${clipboardPath} | wc -c`), () => makeCheckResult(), () => []))
        .resolves.toMatchObject({ action: "allow" });
      for (const command of [`cp ${clipboardPath} /tmp/project/copy.png`, `cat ${clipboardPath} /etc/hosts`, `cat ${clipboardPath} > /tmp/out`]) {
        const result = await describeBashExternalDirectoryGate(context(command), () => makeCheckResult(), () => []);
        expect(result).not.toMatchObject({ action: "allow" });
      }
    } finally {
      rmSync(clipboardPath, { force: true });
    }
  });
});

describe("describeBashExternalDirectoryGate agent directory reads", () => {
  const context = (command: string) => ({
    toolName: "bash",
    agentName: null,
    input: { command },
    toolCallId: "call-agent",
    cwd,
    sandboxed: true,
  });

  it.each(["cat ~/.pi/agent/settings.json", "cat ~/.pi/agent/settings.json | head -5"])("auto-allows %s", async (command) => {
    const result = await describeBashExternalDirectoryGate(context(command), () => makeCheckResult(), () => []);
    expect(result).toMatchObject({ action: "allow" });
  });

  it.each(["echo x > ~/.pi/agent/settings.json", "cp /etc/hosts ~/.pi/agent/settings.json"])("does not auto-allow %s", async (command) => {
    const result = await describeBashExternalDirectoryGate(context(command), () => makeCheckResult(), () => []);
    expect(result).not.toMatchObject({ action: "allow" });
  });
});
