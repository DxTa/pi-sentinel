import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { AUTO_MODE_BUILD_ID } from "./auto-mode-build";
import { AutoModeWorkerServer } from "./auto-mode-worker";
import piPermissionSystemExtension from "./index.ts";

const tempPaths: string[] = [];
const workers: AutoModeWorkerServer[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  delete process.env.PI_CODING_AGENT_DIR;
  delete process.env.PI_SENTINEL_AUTO_SOCKET;
  await Promise.all(workers.splice(0).map((worker) => worker.close()));
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
  if (mode === "yolo" || mode === "auto") {
    // A classifier that never finishes loading: requests that reach it fail closed and prompt, with no real model.
    const socketPath = path.join(agentDir, "auto.sock");
    process.env.PI_SENTINEL_AUTO_SOCKET = socketPath;
    const worker = new AutoModeWorkerServer({
      socketPath,
      buildId: AUTO_MODE_BUILD_ID,
      provider: { ready: async () => undefined, classify: async () => { throw new Error("model_loading"); } },
    });
    await worker.start();
    workers.push(worker);
  }
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
  return { pi, projectDir, context, run };
}

async function writeSshRemote(repoDir: string): Promise<void> {
  await mkdir(path.join(repoDir, ".git"));
  await writeFile(
    path.join(repoDir, ".git", "config"),
    '[remote "origin"]\n\turl = git@github.com:example/repo.git\n',
    "utf8",
  );
}

const SSH_REMOTE = "git@example.test:org/repo.git";

describe("yolo mode hard rules", () => {
  it.each([
    ["write", { path: "/etc/yolo-test", content: "x" }],
    ["edit", { path: "/usr/bin/yolo-test", oldText: "a", newText: "b" }],
    ["bash", { command: "echo x > /etc/yolo-test" }],
    ["bash", { command: "for f in a; do cp $f /usr/bin/yolo-test; done" }],
  ])("asks before writing %s into a forbidden path and blocks on refusal", async (toolName, input) => {
    const { run, context } = await setup("yolo");
    context.ui.select.mockImplementation(async () => "No");
    const result = await run(toolName, input);

    expect(result).toMatchObject({ block: true });
    expect(result?.reason).toContain("yolo");
    expect(context.ui.select).toHaveBeenCalledOnce();
    const [title, choices] = context.ui.select.mock.calls[0] as unknown as [string, string[]];
    expect(title).toContain("BLOCKED BY POLICY");
    expect(choices).toEqual(["Yes", "Yes, for this session", "No", "No, provide reason"]);
  });

  it("allows a forbidden write once when the user approves, and asks again next time", async () => {
    const { run, context } = await setup("yolo");
    const input = { path: "/etc/yolo-test", content: "x" };

    expect((await run("write", input))?.block).toBeUndefined();
    expect((await run("write", input))?.block).toBeUndefined();
    // Each run asks for the policy deny and, with the classifier unavailable, once more for the external write.
    expect(context.ui.select).toHaveBeenCalledTimes(4);
  });

  it("does not apply the forbidden-path deny in manual mode", async () => {
    const { run } = await setup("manual");
    const result = await run("write", { path: "/etc/yolo-test", content: "x" });

    expect(result?.reason ?? "").not.toContain("yolo mode");
  });

  it.each([
    ["write", (dir: string) => ({ path: path.join(dir, "..", "yolo-outside.txt"), content: "x" })],
    ["bash", () => ({ command: "cat /etc/hosts" })],
    ["bash", () => ({ command: "echo x > /tmp/yolo-test" })],
  ])("prompts for external %s when the classifier is unavailable", async (toolName, makeInput) => {
    const { run, context, projectDir } = await setup("yolo");
    await run(toolName, makeInput(projectDir));

    expect(context.ui.select).toHaveBeenCalled();
  });

  it.each([
    ["bash", () => ({ command: "docker ps" })],
    ["bash", () => ({ command: "git pull" })],
    ["bash", () => ({ command: "kubectl get pods" })],
  ])("lets %s run without a prompt", async (toolName, makeInput) => {
    const { run, context, projectDir } = await setup("yolo");
    const result = await run(toolName, makeInput(projectDir));

    expect(result?.block).toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it.each([
    "rm notes.txt",
    "cd src && rm -rf build",
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

  it("prompts once for a git push to an SSH remote instead of blocking it when SRT is disabled", async () => {
    const { run, context, projectDir } = await setup("manual");
    await writeSshRemote(projectDir);

    const result = await run("bash", { command: "git push origin main" });

    expect(result?.block).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledOnce();
    expect(context.ui.select.mock.calls[0]?.[1]).toEqual(["Yes", "No", "No, provide reason"]);
  });

  it("blocks a git push to an SSH remote when the one-time prompt is denied", async () => {
    const { run, context, projectDir } = await setup("manual");
    await writeSshRemote(projectDir);
    context.ui.select.mockResolvedValueOnce("No");

    expect(await run("bash", { command: "git push origin main" })).toMatchObject({ block: true });
    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it("auto-approves a git push to an SSH remote in yolo mode when SRT is disabled", async () => {
    const { run, context, projectDir } = await setup("yolo");
    await writeSshRemote(projectDir);

    expect((await run("bash", { command: "git push origin main" }))?.block).toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("still blocks an SSH segment chained before a git push in a tool call", async () => {
    const { run, projectDir } = await setup("manual");
    await writeSshRemote(projectDir);

    expect(await run("bash", { command: "ssh host ls; git push origin main" })).toMatchObject({
      block: true,
      reason: expect.stringContaining("implicit credential access"),
    });
  });

  it("still blocks an SSH segment chained before a git push in user bash", async () => {
    const { pi, context, projectDir } = await setup("manual");
    await writeSshRemote(projectDir);

    const result = await pi.handlers.get("user_bash")?.(
      { command: "ssh host ls; git push origin main", cwd: projectDir },
      context as never,
    );

    expect(result).not.toHaveProperty("operations");
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("still blocks a git fetch into another repo chained after a git push", async () => {
    const { run } = await setup("manual");
    const otherRepo = await makeTempDir("pi-yolo-other-");
    await writeSshRemote(otherRepo);

    expect(await run("bash", { command: `git push git@example.test:org/repo.git main; git -C ${otherRepo} fetch origin` })).toMatchObject({
      block: true,
    });
  });

  it.each([
    "git remote update && git push URL main",
    "git -C OTHER fe't'ch origin && git push URL main",
    "git push URL main $(SSHWORD host ls)",
  ])("still blocks a chain that hides a remote or credential segment: %s", async (template) => {
    const { run } = await setup("manual");
    const otherRepo = await makeTempDir("pi-yolo-other-");
    await writeSshRemote(otherRepo);
    const command = template.replace("URL", SSH_REMOTE).replace("OTHER", otherRepo).replace("SSHWORD", "ssh");

    expect(await run("bash", { command })).toMatchObject({ block: true });
  });

  it("keeps local git commands in a push chain on the one-time prompt", async () => {
    const { run, context } = await setup("manual");

    expect((await run("bash", { command: "git add -A && git commit -m x && git push " + SSH_REMOTE + " main" }))?.block).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it.each([
    "git -c core.sshCommand=x push @REMOTE@ main",
    "git commit -S -m x; git push @REMOTE@ main",
    "git -C . tag -s v1; git push @REMOTE@ main",
  ])("still blocks a push chain with a non-plain git form or signing flag: %s", async (template) => {
    const { run, projectDir } = await setup("manual");
    await writeSshRemote(projectDir);

    expect(await run("bash", { command: template.replace("@REMOTE@", SSH_REMOTE) })).toMatchObject({ block: true });
  });

  it("asks for external network exec while the classifier is unavailable, and never prompts for a denied domain", async () => {
    const { run, context } = await setup("yolo", { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: ["blocked.test"] });
    context.ui.select.mockImplementation(async () => "No");

    expect(await run("bash", { command: "curl https://example.test" })).toMatchObject({ block: true });
    expect(context.ui.select).toHaveBeenCalled();
    expect(await run("bash", { command: "curl -o /etc/yolo-test https://example.test" })).toMatchObject({ block: true });
    const before = context.ui.select.mock.calls.length;
    expect(await run("bash", { command: "curl https://blocked.test" })).toMatchObject({ block: true });
    expect(context.ui.select.mock.calls.length).toBe(before);
  });

  it.each(["manual", "auto"])("keeps prompting for a write outside the workspace in %s mode", async (mode) => {
    const { run, context, projectDir } = await setup(mode);
    await run("write", { path: path.join(projectDir, "..", "yolo-outside.txt"), content: "x" });

    expect(context.ui.select).toHaveBeenCalled();
  });

  it("does not hard-deny an external Bash write in yolo; it asks only because the classifier is unavailable", async () => {
    const { run, context } = await setup("yolo");
    const result = await run("bash", { command: "touch /opt/yolo-shared/notes.txt" });

    expect(result?.block).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledOnce();
    const [title] = context.ui.select.mock.calls[0] as unknown as [string];
    expect(title).not.toContain("BLOCKED BY POLICY");
  });

  it.each(["/bin/rm notes.txt", "rm\tnotes.txt", "kubectl uncordon node-a"])("prompts for %s", async (command) => {
    const { run, context } = await setup("yolo");
    await run("bash", { command });

    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it("asks before an explicitly denied Git push and blocks on refusal", async () => {
    const { run, context } = await setup(
      "manual",
      { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: [] },
      { "*": "ask", bash: { "git *": "deny" } },
    );
    context.ui.select.mockImplementation(async () => "No");

    await expect(run("bash", { command: "git push https://example.com/repo.git main" }))
      .resolves.toMatchObject({ block: true });
    expect(context.ui.select).toHaveBeenCalledOnce();
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
