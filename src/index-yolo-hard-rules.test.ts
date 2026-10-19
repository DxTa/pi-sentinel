import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import piPermissionSystemExtension from "./index.ts";

const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  delete process.env.PI_CODING_AGENT_DIR;
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

interface FakePi {
  handlers: Map<string, (event: unknown, ctx: unknown) => unknown>;
  commands: Map<string, unknown>;
  on: (name: string, handler: (event: unknown, ctx: unknown) => unknown) => void;
  registerCommand: (name: string, command: unknown) => void;
  getAllTools: () => string[];
  setActiveTools: (names: string[]) => void;
  events: {
    on: (name: string, handler: (event: unknown) => unknown) => () => void;
    emit: (name: string, payload: unknown) => void;
  };
}

function createFakePi(toolNames: string[] = ["bash"]): FakePi {
  const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
  const commands = new Map<string, unknown>();
  const eventHandlers = new Map<string, Array<(event: unknown) => unknown>>();
  return {
    handlers,
    commands,
    on: (name, handler) => {
      handlers.set(name, handler);
    },
    registerCommand: (name, command) => {
      commands.set(name, command);
    },
    getAllTools: () => toolNames,
    setActiveTools: vi.fn(),
    events: {
      on: (name, handler) => {
        const list = eventHandlers.get(name) ?? [];
        list.push(handler);
        eventHandlers.set(name, list);
        return () => {
          const current = eventHandlers.get(name) ?? [];
          eventHandlers.set(name, current.filter((item) => item !== handler));
        };
      },
      emit: (name, payload) => {
        for (const handler of eventHandlers.get(name) ?? []) handler(payload);
      },
    },
  };
}

function createContext(cwd: string, options: { hasUI?: boolean; choices?: string[] } = {}) {
  const choices = [...(options.choices ?? [])];
  return {
    cwd,
    hasUI: options.hasUI ?? false,
    ui: {
      notify: vi.fn(),
      setStatus: vi.fn(),
      select: vi.fn(async () => choices.shift()),
    },
    sessionManager: {
      getEntries: () => [],
      getSessionDir: () => null,
    },
  };
}


async function setup(
  mode: string,
  network: Record<string, unknown> = { enabled: false, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
  permission: Record<string, unknown> = { "*": "ask", bash: { "*": "ask" } },
) {
  const agentDir = await makeTempDir("pi-yolo-agent-");
  const projectDir = await makeTempDir("pi-yolo-project-");
  process.env.PI_CODING_AGENT_DIR = agentDir;
  await writeFile(
    path.join(agentDir, "permissions.json"),
    JSON.stringify({
      mode,
      yoloAskBashPatterns: [],
      permission,
      network,
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    }),
    "utf8",
  );
  const pi = createFakePi(["bash", "write", "edit", "read"]);
  piPermissionSystemExtension(pi as never);
  const context = createContext(projectDir, { hasUI: true, choices: Array(10).fill("Yes") });
  const run = (toolName: string, input: Record<string, unknown>) =>
    pi.handlers.get("tool_call")?.({ toolName, toolCallId: "t-" + Math.random(), input }, context as never) as Promise<{ block?: true; reason?: string } | undefined>;
  return { projectDir, context, run };
}

describe("yolo mode hard rules", () => {
  it.each([
    ["write", { path: "/etc/yolo-test", content: "x" }],
    ["edit", { path: "/usr/bin/yolo-test", oldText: "a", newText: "b" }],
    ["bash", { command: "echo x > /etc/yolo-test" }],
    ["bash", { command: "for f in a; do cp $f /usr/bin/yolo-test; done" }],
  ])("denies %s into a forbidden path without asking", async (toolName, input) => {
    const { run, context } = await setup("yolo");
    const result = await run(toolName, input);

    expect(result).toMatchObject({ block: true });
    expect(result?.reason).toContain("yolo");
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("does not apply the forbidden-path deny in manual mode", async () => {
    const { run } = await setup("manual");
    const result = await run("write", { path: "/etc/yolo-test", content: "x" });

    expect(result?.reason ?? "").not.toContain("yolo mode");
  });

  it.each([
    ["write", (dir: string) => ({ path: path.join(dir, "..", "yolo-outside.txt"), content: "x" })],
    ["bash", () => ({ command: "cat /etc/hosts" })],
    ["bash", () => ({ command: "docker ps" })],
    ["bash", () => ({ command: "git pull" })],
    ["bash", () => ({ command: "kubectl get pods" })],
    ["bash", () => ({ command: "echo x > /tmp/yolo-test" })],
  ])("lets %s run without a prompt", async (toolName, makeInput) => {
    const { run, context, projectDir } = await setup("yolo");
    const result = await run(toolName, makeInput(projectDir));

    expect(result?.block).toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it.each([
    "rm notes.txt",
    "cd src && rm -rf build",
    "git push origin main",
    "kubectl apply -f x.yaml",
    "kubectl set image deploy/a a=b",
    "kubectl delete pod a",
  ])("still prompts for %s", async (command) => {
    const { run, context } = await setup("yolo");
    await run("bash", { command });

    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it("blocks host SSH when the SRT credential boundary is disabled", async () => {
    const { run, context } = await setup("yolo");
    const result = await run("bash", { command: "ssh host ls" });

    expect(result).toMatchObject({
      block: true,
      reason: expect.stringContaining("implicit credential access requires the SRT read-only boundary"),
    });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("auto-approves network asks and still denies forbidden writes before any network prompt", async () => {
    const { run, context } = await setup("yolo", { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: ["blocked.test"] });

    expect((await run("bash", { command: "curl https://example.test" }))?.block).toBeUndefined();
    expect(await run("bash", { command: "curl -o /etc/yolo-test https://example.test" })).toMatchObject({ block: true });
    expect(await run("bash", { command: "curl https://blocked.test" })).toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it.each(["manual", "yolo-auto"])("keeps prompting for a write outside the workspace in %s mode", async (mode) => {
    const { run, context, projectDir } = await setup(mode);
    await run("write", { path: path.join(projectDir, "..", "yolo-outside.txt"), content: "x" });

    expect(context.ui.select).toHaveBeenCalled();
  });

  it("does not hard-deny or force a prompt for an external Bash write in yolo", async () => {
    const { run, context } = await setup("yolo");
    const result = await run("bash", { command: "touch /opt/yolo-shared/notes.txt" });

    expect(result?.block).toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it.each(["/bin/rm notes.txt", "rm\tnotes.txt", "kubectl uncordon node-a"])("prompts for %s", async (command) => {
    const { run, context } = await setup("yolo");
    await run("bash", { command });

    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it("blocks an explicitly denied Git push without a dialog", async () => {
    const { run, context } = await setup(
      "manual",
      { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: [] },
      { "*": "ask", bash: { "git *": "deny" } },
    );

    await expect(run("bash", { command: "git push https://example.com/repo.git main" }))
      .resolves.toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("uses one-time approval for Git pushes through earlier Bash gates", async () => {
    const { run, context } = await setup("manual");
    const outsideDir = await makeTempDir("pi-yolo-outside-");
    const command = `git -C ${outsideDir} push origin main`;

    await run("bash", { command });
    const firstPromptCount = context.ui.select.mock.calls.length;
    await run("bash", { command });

    expect(firstPromptCount).toBeGreaterThan(0);
    expect(context.ui.select.mock.calls.length).toBeGreaterThan(firstPromptCount);
    for (const [, choices] of context.ui.select.mock.calls) {
      expect(choices).toEqual(["Yes", "No", "No, provide reason"]);
    }
  });
});
