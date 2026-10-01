import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { chmod, mkdir, mkdtemp, realpath, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import piPermissionSystemExtension from "./index.ts";
import { resolveDockerSocketPaths } from "./sandbox/docker-socket.js";
import { YOLO_AUTO_BUILD_ID } from "./yolo-auto-build";
import { YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema";
import type { YoloAutoHeads } from "./yolo-auto-policy";
import { YoloAutoWorkerServer } from "./yolo-auto-worker";

const tempPaths: string[] = [];
const canSimulateReadOnlyDirectory = process.platform !== "win32" && process.getuid?.() !== 0;

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  delete process.env.PI_CODING_AGENT_DIR;
  delete process.env.PI_SENTINEL_YOLO_AUTO_SOCKET;
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

async function writeExtensionConfig(agentDir: string, overrides: Record<string, unknown> = {}) {
  await mkdir(path.join(agentDir, "extensions", "pi-sentinel"), { recursive: true });
  const baseConfig = {
    mode: "manual",
    permission: {
      "*": "deny",
      bash: {
        "echo ok": "allow",
        "pwd": "allow",
        "*sandbox-run.mjs*": "deny",
      },
    },
    network: { enabled: false, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
    sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: [] },
  };
  const sandboxOverride = overrides.sandbox;
  const sandbox = sandboxOverride && typeof sandboxOverride === "object" && Array.isArray(sandboxOverride) === false
    ? { ...baseConfig.sandbox, ...(sandboxOverride as Record<string, unknown>) }
    : baseConfig.sandbox;
  await writeFile(
    path.join(agentDir, "permissions.json"),
    JSON.stringify({ ...baseConfig, ...overrides, sandbox }),
    "utf8",
  );
}

function safeYoloAutoHeads(action: string): YoloAutoHeads {
  const winners: Record<string, string> = {
    injection: "benign",
    routing: "tool_operation_request",
    sensitive_document: "source_code",
    threat: "benign",
    tool_action: action,
    tool_class: "file",
  };
  return {
    ...Object.fromEntries(
      Object.entries(YOLO_AUTO_LABEL_SCHEMA)
        .filter(([head]) => head !== "tool_tags")
        .map(([head, labels]) => [
          head,
          Object.fromEntries(labels.map((label) => [
            label,
            label === winners[head] ? 0.99 : 0.01 / (labels.length - 1),
          ])),
        ]),
    ),
    tool_tags: { "source:sensitive": 0.1, "source:untrusted": 0.1, "sink:external": 0.1 },
  } as YoloAutoHeads;
}

function extractHelperInput(command: string) {
  const fileMatch = command.match(/PI_SRT_HELPER_INPUT_FILE=(?:'([^']*)'|([^\s]+))/);
  const file = fileMatch?.[1] || fileMatch?.[2];
  if (file) {
    const input = JSON.parse(readFileSync(file, "utf8"));
    rmSync(path.dirname(file), { recursive: true, force: true });
    return input;
  }
  const match = command.match(/PI_SRT_HELPER_INPUT_B64=([^\s]+)\s/);
  if (!match) throw new Error(`Missing helper input in command: ${command}`);
  return JSON.parse(Buffer.from(match[1]!, "base64").toString("utf8"));
}

describe("piPermissionSystemExtension SRT default smoke", () => {
  it("captures E2BIG result metadata from final wrapped Bash input", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, { debugLog: true });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const toolCallEvent = { toolName: "bash", input: { command: "echo ok" } };
    await pi.handlers.get("tool_call")?.(toolCallEvent, context as never);
    expect(toolCallEvent.input.command).toContain("PI_SRT_HELPER_INPUT_B64=");

    const toolResult = pi.handlers.get("tool_result");
    expect(toolResult).toBeDefined();
    const logPath = path.join(agentDir, "extensions", "pi-sentinel", "logs", "pi-sentinel-debug.jsonl");
    const readDiagnostics = async () => (await readFile(logPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .filter((record) => record.event === "spawn.e2big");

    await toolResult?.({
      toolName: "bash",
      input: toolCallEvent.input,
      content: [{ type: "text", text: "spawn E2BIG" }],
      isError: true,
    }, context);

    const diagnostics = await readDiagnostics();
    expect(diagnostics).toHaveLength(1);
    const [diagnostic] = diagnostics;
    expect(diagnostic).toMatchObject({
      event: "spawn.e2big",
      route: "pi-bash",
      processEnvironment: {
        totalBytes: expect.any(Number),
        largestVariables: expect.any(Array),
      },
    });
    expect(diagnostic.commandBytes).toBe(Buffer.byteLength(toolCallEvent.input.command));
    expect(diagnostic.srtWrappedCommand).toBe(true);
    expect(JSON.stringify(diagnostic)).not.toContain(toolCallEvent.input.command);

    await toolResult?.({
      toolName: "bash",
      input: toolCallEvent.input,
      content: [{ type: "text", text: "spawn E2BIG\n\nCommand exited with code 1" }],
      isError: true,
    }, context);
    expect(await readDiagnostics()).toHaveLength(1);
  });

  it("cleans spilled helper input after Bash result and logs size-only diagnostics", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      debugLog: true,
      permission: { "*": "allow", bash: { "*": "allow" } },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const command = `echo ${"x".repeat(100_000)}`;
    const toolCallId = "large-helper-payload";
    const toolCallEvent = { toolCallId, toolName: "bash", input: { command } };
    await pi.handlers.get("tool_call")?.(toolCallEvent, context as never);

    expect(toolCallEvent.input.command.length).toBeLessThan(2_000);
    const payloadFile = toolCallEvent.input.command.match(/PI_SRT_HELPER_INPUT_FILE=(?:'([^']+)'|([^\s]+))/);
    const file = payloadFile?.[1] ?? payloadFile?.[2];
    expect(file).toBeDefined();
    expect(existsSync(file!)).toBe(true);
    expect(JSON.parse(await readFile(file!, "utf8")).command).toBe(command);

    await pi.handlers.get("tool_result")?.({
      toolCallId,
      toolName: "bash",
      input: toolCallEvent.input,
      content: [{ type: "text", text: "spawn E2BIG" }],
      isError: true,
    }, context as never);

    expect(existsSync(file!)).toBe(false);
    const logPath = path.join(agentDir, "extensions", "pi-sentinel", "logs", "pi-sentinel-debug.jsonl");
    const diagnostics = (await readFile(logPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .filter((record) => record.event === "spawn.e2big");
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rawCommandBytes: Buffer.byteLength(command),
      helperPayloadBytes: expect.any(Number),
    });
    expect(JSON.stringify(diagnostics)).not.toContain(command);
  });

  it("returns upstream permission blocks instead of continuing", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const event = { toolName: "bash", input: { command: "echo denied" } };
    const result = await pi.handlers.get("tool_call")?.(event, createContext(projectDir) as never);

    expect(result).toMatchObject({ block: true });
    expect(event.input.command).toBe("echo denied");
  });

  it("permission-checks original bash command before rewriting to SRT helper", { timeout: 30_000 }, async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);

    const event = { toolName: "bash", input: { command: "echo ok" } };
    const result = await pi.handlers.get("tool_call")?.(event, createContext(projectDir) as never);

    expect(result).toBeUndefined();
    expect(event.input.command).toContain("sandbox-run.mjs");
    expect(event.input.command).toContain("PI_SRT_HELPER_INPUT_B64=");
  });

  it("keeps Bash host-accessible while local file tools use workspace policy", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        path: { "*": "allow" },
        write: "deny",
        external_directory: { "*": "allow" },
      },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
    });

    const pi = createFakePi(["bash", "write"]);
    piPermissionSystemExtension(pi as never);
    const commandEvent = { toolName: "bash", input: { command: "printf 'host && command'" } };
    const commandResult = await pi.handlers.get("tool_call")?.(
      commandEvent,
      createContext(projectDir) as never,
    );

    expect(commandResult).toBeUndefined();
    expect(commandEvent.input.command).toBe("printf 'host && command'");

    const writeEvent = {
      toolName: "write",
      input: { path: path.join(projectDir, "blocked.txt"), content: "blocked" },
    };
    const writeResult = await pi.handlers.get("tool_call")?.(
      writeEvent,
      createContext(projectDir) as never,
    );

    expect(writeResult).toEqual({});
  });

  it("auto-allows curated diagnostics for unsandboxed host Bash", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      mode: "yolo-auto",
      yoloAskBashPatterns: [],
      permission: { "*": "ask", bash: { "*": "ask" }, path: { "*": "allow" }, external_directory: { "*": "allow" } },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Yes"] });
    const result = await pi.handlers.get("tool_call")?.(
      { toolName: "bash", toolCallId: "host-diagnostic", input: { command: "docker ps" } },
      context as never,
    );

    expect(result).toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("learns repeated safe approvals for unsandboxed host Bash", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      mode: "yolo-auto",
      yoloAskBashPatterns: [],
      permission: { "*": "ask", bash: { "*": "ask" }, path: { "*": "allow" }, external_directory: { "*": "allow" } },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, {
      hasUI: true,
      choices: ["Yes", "Yes", "Yes"],
    });
    const call = pi.handlers.get("tool_call")!;

    for (let index = 0; index < 3; index++) {
      await expect(call(
        { toolName: "bash", toolCallId: "host-read-" + index, input: { command: "ls" } },
        context as never,
      )).resolves.toBeUndefined();
    }
    expect(context.ui.select).toHaveBeenCalledTimes(3);

    await expect(call(
      { toolName: "bash", toolCallId: "host-read-4", input: { command: "ls" } },
      context as never,
    )).resolves.toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledTimes(3);
  });

  it.each(["manual", "yolo", "yolo-auto"] as const)(
    "auto-approves normal workspace file tools in %s mode",
    async (mode) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      process.env.PI_CODING_AGENT_DIR = agentDir;
      const existingPath = path.join(projectDir, "notes.txt");
      await writeFile(existingPath, "needle\\n", "utf8");
      await writeExtensionConfig(agentDir, {
        mode,
        permission: {
          "*": "deny",
          path: { "*": "allow" },
          external_directory: { "*": "deny" },
          read: "deny",
          write: "deny",
          edit: "deny",
          grep: "deny",
          find: "deny",
          ls: "deny",
        },
        sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
      });

      const pi = createFakePi(["bash", "read", "write", "edit", "grep", "find", "ls"]);
      piPermissionSystemExtension(pi as never);
      const toolCall = pi.handlers.get("tool_call")!;
      const context = createContext(projectDir);
      const events = [
        { toolName: "read", input: { path: existingPath } },
        { toolName: "write", input: { path: path.join(projectDir, "new.txt"), content: "new" } },
        { toolName: "edit", input: { path: existingPath, oldText: "needle", newText: "changed" } },
        { toolName: "grep", input: { pattern: "needle", path: projectDir } },
        { toolName: "find", input: { path: projectDir } },
        { toolName: "ls", input: {} },
      ];

      for (const event of events) {
        await expect(toolCall(event, context as never)).resolves.toEqual({});
      }
    },
  );

  it("routes eligible workspace operations through YoloAuto before auto-allow", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const existingPath = path.join(projectDir, "notes.txt");
    await writeFile(existingPath, "before\n", "utf8");
    await writeExtensionConfig(agentDir, {
      mode: "yolo-auto",
      permission: {
        "*": "ask",
        read: "ask",
        write: "ask",
        edit: "ask",
        path: { "*": "allow" },
      },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: [] },
    });

    const socketPath = path.join(agentDir, "yolo-auto-test.sock");
    process.env.PI_SENTINEL_YOLO_AUTO_SOCKET = socketPath;
    const classificationTexts: string[] = [];
    const worker = new YoloAutoWorkerServer({
      socketPath,
      buildId: YOLO_AUTO_BUILD_ID,
      provider: {
        ready: async () => undefined,
        classify: async (text) => {
          classificationTexts.push(text);
          const action = text.startsWith("tool=bash ")
            ? "exec"
            : text.startsWith("tool=write ") || text.startsWith("tool=edit ")
              ? "write"
              : text.startsWith("tool=ls ")
                ? "list"
                : "read";
          return safeYoloAutoHeads(action);
        },
      },
    });
    await worker.start();
    const random = vi.spyOn(Math, "random").mockReturnValue(1);
    const pi = createFakePi(["bash", "read", "write", "edit", "ls"]);
    piPermissionSystemExtension(pi as never);
    const toolCall = pi.handlers.get("tool_call")!;
    const context = createContext(projectDir);

    try {
      const events = [
        { toolName: "read", input: { path: existingPath } },
        { toolName: "ls", input: {} },
        { toolName: "write", input: { path: path.join(projectDir, "new.txt"), content: "new" } },
        { toolName: "edit", input: { path: existingPath, oldText: "before", newText: "after" } },
        { toolName: "bash", input: { command: "printf 'safe'" } },
      ];
      for (const event of events) await toolCall(event, context as never);
      expect(classificationTexts).toHaveLength(events.length);
      expect(classificationTexts.map((text) => text.split(" ", 1)[0])).toEqual([
        "tool=read", "tool=ls", "tool=write", "tool=edit", "tool=bash",
      ]);
    } finally {
      random.mockRestore();
      await pi.handlers.get("session_shutdown")?.(undefined, context as never);
      await worker.close();
    }
  });

  it("keeps external paths gated", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await makeTempDir("pi-permission-outside-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        path: { "*": "allow" },
        external_directory: { "*": "deny" },
        read: "deny",
      },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi(["bash", "read"]);
    piPermissionSystemExtension(pi as never);
    const result = await pi.handlers.get("tool_call")?.(
      { toolName: "read", input: { path: path.join(outsideDir, "secret.txt") } },
      createContext(projectDir) as never,
    );

    expect(result).toMatchObject({ block: true });
  });

  it("rejects symlink escapes instead of treating them as workspace-local", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await makeTempDir("pi-permission-outside-");
    const outsidePath = path.join(outsideDir, "secret.txt");
    const linkPath = path.join(projectDir, ".env.local");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeFile(outsidePath, "secret", "utf8");
    await symlink(outsidePath, linkPath);
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        path: { "*": "allow" },
        external_directory: { "*": "deny" },
        read: "deny",
      },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi(["bash", "read"]);
    piPermissionSystemExtension(pi as never);
    const result = await pi.handlers.get("tool_call")?.(
      { toolName: "read", input: { path: linkPath } },
      createContext(projectDir) as never,
    );

    expect(result).toMatchObject({ block: true });
  });

  it.each(["manual", "yolo", "yolo-auto"] as const)(
    "blocks canonical symlink writes in %s mode",
    async (mode) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      const outsideDir = await makeTempDir("pi-permission-outside-");
      const linkDir = path.join(projectDir, "linked");
      const outsideFile = path.join(outsideDir, "existing.txt");
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeFile(outsideFile, "old", "utf8");
      await symlink(outsideDir, linkDir);
      await writeExtensionConfig(agentDir, {
        mode,
        permission: {
          "*": "allow",
          path: { "*": "allow" },
          external_directory: { "*": "allow" },
          write: "deny",
          edit: "deny",
        },
        sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
      });

      const pi = createFakePi(["bash", "write", "edit"]);
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir, { hasUI: true });
      await expect(pi.handlers.get("tool_call")?.(
        { toolName: "write", input: { path: path.join(linkDir, "new.txt"), content: "new" } },
        context as never,
      )).resolves.toMatchObject({ block: true });
      await expect(pi.handlers.get("tool_call")?.(
        { toolName: "edit", input: { path: path.join(linkDir, "existing.txt"), oldText: "old", newText: "new" } },
        context as never,
      )).resolves.toMatchObject({ block: true });
    },
  );

  it("allows a canonical .env read when result scanning is enabled", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeFile(envPath, "TOKEN=secret", "utf8");
    await writeExtensionConfig(agentDir, {
      sentinelCreds: { enabled: true, resultScanning: true },
      permission: {
        "*": "deny",
        path: { "*": "allow", "*.env": "deny", "*.env.*": "deny" },
        external_directory: { "*": "deny" },
        read: "deny",
      },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi(["bash", "read"]);
    piPermissionSystemExtension(pi as never);
    await expect(pi.handlers.get("tool_call")?.(
      { toolName: "read", input: { path: envPath } },
      createContext(projectDir) as never,
    )).resolves.toEqual({});
  });

  it("keeps .env reads and selectors gated when result scanning is disabled", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env.local");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeFile(envPath, "TOKEN=secret", "utf8");
    await writeExtensionConfig(agentDir, {
      sentinelCreds: { enabled: true, resultScanning: false },
      permission: {
        "*": "allow",
        path: { "*": "allow", "*.env": "deny", "*.env.*": "deny" },
        external_directory: { "*": "allow" },
        read: "allow",
        grep: "deny",
      },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi(["bash", "read", "grep"]);
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    await expect(pi.handlers.get("tool_call")?.(
      { toolName: "read", input: { path: envPath } },
      context as never,
    )).resolves.toMatchObject({ block: true });
    await expect(pi.handlers.get("tool_call")?.(
      { toolName: "grep", input: { path: projectDir, glob: ".env*", pattern: "." } },
      context as never,
    )).resolves.toMatchObject({ block: true });
  });

  it("keeps workspace .env writes protected", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        path: { "*": "allow", "*.env": "deny", "*.env.*": "deny" },
        external_directory: { "*": "allow" },
        write: "allow",
        edit: "allow",
      },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi(["bash", "write", "edit"]);
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);

    for (const envName of [".env", ".env.local", ".env.example"]) {
      await expect(pi.handlers.get("tool_call")?.(
        { toolName: "write", input: { path: path.join(projectDir, envName), content: "TOKEN=secret" } },
        context as never,
      )).resolves.toMatchObject({ block: true });
      await expect(pi.handlers.get("tool_call")?.(
        { toolName: "edit", input: { path: path.join(projectDir, envName), oldText: "TOKEN=old", newText: "TOKEN=new" } },
        context as never,
      )).resolves.toMatchObject({ block: true });
    }
  });

  it("hard-blocks host Bash mutation outside safe roots", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        external_directory: { "*": "allow" },
      },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const command = "rm -rf /etc/passwd";
    const toolEvent = { toolName: "bash", input: { command } };
    const toolResult = await pi.handlers.get("tool_call")?.(
      toolEvent,
      createContext(projectDir) as never,
    );
    expect(toolResult).toMatchObject({ block: true });
    expect(toolEvent.input.command).toBe(command);

    const userResult = await pi.handlers.get("user_bash")?.(
      { command, cwd: projectDir },
      createContext(projectDir) as never,
    );
    expect(userResult).toMatchObject({
      result: { exitCode: 1, output: expect.stringContaining("Blocked mutating Bash command") },
    });
  });

  it("allows Docker commands by default in the online profile", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        external_directory: { "*": "allow" },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const event = { toolName: "bash", input: { command: "docker info" } };
    const result = await pi.handlers.get("tool_call")?.(
      event,
      createContext(projectDir) as never,
    );

    const dockerSockets = resolveDockerSocketPaths();
    if (dockerSockets.length === 0) {
      expect(result).toMatchObject({ block: true, reason: "Docker socket unavailable; command blocked." });
      return;
    }

    expect(result).toBeUndefined();
    const helperInput = extractHelperInput(event.input.command);
    expect(helperInput.runtimeConfig.network.allowUnixSockets).toEqual(
      expect.arrayContaining(dockerSockets),
    );
    if (existsSync(path.join(homedir(), ".docker/config.json"))) {
      expect(helperInput.runtimeConfig.filesystem.allowRead).toContain(
        path.join(homedir(), ".docker/config.json"),
      );
    }
  });

  it.each(["manual", "yolo-auto"] as const)("auto-allows trusted Pi skill/extension reads and scripts in %s mode", async (mode) => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const skillDir = path.join(agentDir, "skills", "demo");
    await mkdir(skillDir, { recursive: true });
    await writeFile(path.join(skillDir, "SKILL.md"), "# demo\n", "utf8");
    await writeFile(path.join(skillDir, "run.sh"), "echo hi\n", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      mode,
      permission: {
        "*": "ask",
        bash: { "*": "ask" },
        external_directory: { "*": "ask" },
      },
    });

    const pi = createFakePi(["bash", "read", "write"]);
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true });
    const handler = pi.handlers.get("tool_call")!;

    const read = await handler({ toolName: "read", toolCallId: "t-read", input: { path: path.join(skillDir, "SKILL.md") } }, context as never);
    const scriptCommand = `bash ${path.join(skillDir, "run.sh")}`;
    const scriptEvent = { toolName: "bash", toolCallId: "t-bash", input: { command: scriptCommand } };
    const script = await handler(scriptEvent, context as never);
    expect(scriptEvent.input.command).toBe(scriptCommand);
    expect(JSON.stringify(read ?? {})).not.toContain('"block":true');
    expect(JSON.stringify(script ?? {})).not.toContain('"block":true');
    expect(context.ui.select).not.toHaveBeenCalled();

    await handler({ toolName: "write", toolCallId: "t-write", input: { path: path.join(skillDir, "new.sh"), content: "x" } }, context as never);
    expect(context.ui.select).toHaveBeenCalled();
  });

  it("includes Pi infrastructure directories in SRT read paths", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const agentsDir = path.join(agentDir, "agents");
    const indexPath = path.join(agentsDir, "agents-index.tsv");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await mkdir(agentsDir, { recursive: true });
    await writeFile(indexPath, "agent\tdescription\n", "utf8");
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        external_directory: { "*": "allow" },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const event = { toolName: "bash", input: { command: `cat ${indexPath}` } };
    const result = await pi.handlers.get("tool_call")?.(
      event,
      createContext(projectDir) as never,
    );

    expect(result).toBeUndefined();
    const helperInput = extractHelperInput(event.input.command);
    expect(helperInput.runtimeConfig.filesystem.allowRead.some((entry) => entry.endsWith(path.basename(agentDir)))).toBe(true);
  });

  it("uses git repo root when command runs from a subdirectory", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const subdir = path.join(projectDir, "packages", "app");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await mkdir(subdir, { recursive: true });
    execFileSync("git", ["init"], { cwd: projectDir, stdio: "ignore" });
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);

    const event = { toolName: "bash", input: { command: "pwd" } };
    await pi.handlers.get("tool_call")?.(event, createContext(subdir) as never);

    const helperInput = extractHelperInput(event.input.command);
    expect(helperInput.runtimeConfig.filesystem.allowRead).toContain(await realpath(projectDir));
  });

  it("completes sandbox grant subcommands and flags without side effects", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const command = pi.commands.get("sandbox-grant") as {
      getArgumentCompletions?: (prefix: string) => unknown[] | Promise<unknown[] | null> | null;
    };

    const subcommands = await command.getArgumentCompletions?.("") as Array<{ value: string }>;
    const pathFlags = await command.getArgumentCompletions?.("path /tmp/external --") as Array<{ value: string }>;

    expect(subcommands.map(({ value }) => value)).toEqual(["path", "network"]);
    expect(pathFlags.map(({ value }) => value)).toEqual([
      "path /tmp/external --ro",
      "path /tmp/external --rw",
      "path /tmp/external --ttl",
    ]);
  });

  it("rejects standalone once grants instead of sharing a timed grant", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const grantCommand = pi.commands.get("sandbox-grant") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };

    await expect(grantCommand.handler("network --domain example.com --ttl once", context))
      .rejects.toThrow("do not support --ttl once");
    await expect(grantCommand.handler(`path ${projectDir} --ro --ttl once`, context))
      .rejects.toThrow("do not support --ttl once");
  });

  it("completes only active sandbox grant IDs without mutating policy", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const grantCommand = pi.commands.get("sandbox-grant") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };
    await grantCommand.handler(`path ${projectDir} --ro`, context);
    const message = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as string;
    const grantId = message.match(/\(([^)]+)\)$/)?.[1];
    expect(grantId).toBeTruthy();

    const revokeCommand = pi.commands.get("sandbox-revoke") as {
      getArgumentCompletions?: (prefix: string) => unknown[] | Promise<unknown[] | null> | null;
    };
    const before = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls.length;
    const items = await revokeCommand.getArgumentCompletions?.(grantId!.slice(0, 8)) as Array<{ value: string }>;

    expect(items.map(({ value }) => value)).toEqual([grantId]);
    expect((context.ui.notify as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(before);
  });

  it("persists and revokes sandbox network capability separately from domain policy", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      network: { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: [] },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "offline-dev" },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const grantCommand = pi.commands.get("sandbox-grant") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };
    const revokeCommand = pi.commands.get("sandbox-revoke") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };
    const listCommand = pi.commands.get("sandbox-status") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };

    await grantCommand.handler("network --domain example.com --ttl always", context);
    await listCommand.handler("", context);
    expect((context.ui.notify as ReturnType<typeof vi.fn>).mock.calls[1]?.[0]).toContain("network");
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8"))).toMatchObject({
      network: { allowedDomains: [] },
      sandbox: { network: true },
    });

    await revokeCommand.handler("sandbox-network-global", context);
    await listCommand.handler("", context);
    const liveStatus = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls[3]?.[0] as string;
    expect(liveStatus).toContain("Active grants: 0");
    expect(liveStatus).toContain("Profile: offline-dev (network: off)");
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8")).sandbox.network).toBeUndefined();

    await grantCommand.handler("network --domain example.com --ttl always", context);
    await pi.handlers.get("session_shutdown")?.({}, context);
    await listCommand.handler("", context);
    const listMessage = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls[5]?.[0] as string;
    const grantId = listMessage.match(/^\s+(sandbox-network-\S+):/m)?.[1];
    expect(grantId).toBe("sandbox-network-global");
    expect(listMessage).toContain("Profile: offline-dev (network: on)");
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8"))).toMatchObject({
      network: { allowedDomains: [] },
      sandbox: { network: true },
    });

    await revokeCommand.handler(grantId!, context);
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8")).sandbox.network).toBeUndefined();
  });

  it("revokes an always sandbox grant from persisted config", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const grantCommand = pi.commands.get("sandbox-grant") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };
    const revokeCommand = pi.commands.get("sandbox-revoke") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };

    await grantCommand.handler(`path ${projectDir} --ro --ttl always`, context);
    const grantMessage = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as string;
    const grantId = grantMessage.match(/\(([^)]+)\)$/)?.[1];
    expect(grantId).toBeTruthy();
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8")).sandbox.roBinds)
      .toContain(await realpath(projectDir));

    await revokeCommand.handler(grantId!, context);
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8")).sandbox?.roBinds ?? [])
      .not.toContain(await realpath(projectDir));
  });

  it.skipIf(!canSimulateReadOnlyDirectory)("keeps persistent path grant live when revoke cannot be saved", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const grantCommand = pi.commands.get("sandbox-grant") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };
    const revokeCommand = pi.commands.get("sandbox-revoke") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };
    const statusCommand = pi.commands.get("sandbox-status") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };

    await grantCommand.handler(`path ${projectDir} --ro --ttl always`, context);
    const grantMessage = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as string;
    const grantId = grantMessage.match(/\(([^)]+)\)$/)?.[1];
    expect(grantId).toBeTruthy();

    const permissionsPath = path.join(agentDir, "permissions.json");
    const replacementPath = path.join(agentDir, "replacement.json");
    await writeFile(replacementPath, JSON.stringify({
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev" },
    }), "utf8");
    await rm(permissionsPath);
    await symlink(replacementPath, permissionsPath);
    await chmod(agentDir, 0o500);
    try {
      await expect(revokeCommand.handler(grantId!, context)).rejects.toThrow();
      await statusCommand.handler("", context);
      const status = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[0] as string;
      expect(status).toContain("Active grants: 1");
      expect(status).toContain(grantId!);
      expect(status).not.toContain("[persistent]");
    } finally {
      await chmod(agentDir, 0o700);
    }
  });

  it.skipIf(!canSimulateReadOnlyDirectory)("rolls back sandbox capability revoke when a later layer cannot be saved", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const legacyTarget = await makeTempDir("pi-permission-legacy-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", network: true },
    });
    await writeFile(
      path.join(legacyTarget, "permissions.jsonc"),
      JSON.stringify({ sandbox: { network: true } }),
      "utf8",
    );
    await symlink(
      path.join(legacyTarget, "permissions.jsonc"),
      path.join(agentDir, "pi-permissions.jsonc"),
    );

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const revokeCommand = pi.commands.get("sandbox-revoke") as {
      handler: (args: string, ctx: unknown) => Promise<void>;
    };
    await chmod(legacyTarget, 0o500);
    try {
      await expect(revokeCommand.handler("sandbox-network-global", context)).rejects.toThrow();
      expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8")).sandbox.network).toBe(true);
    } finally {
      await chmod(legacyTarget, 0o700);
    }
  });

  it("asks for domain and sandbox approval before wrapping an offline network command", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        bash: {
          "echo ok https://example.com": "allow",
        },
      },
      network: { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, {
      hasUI: true,
      choices: ["Allow once", "Allow once"],
    });
    const event = { toolName: "bash", input: { command: "echo ok https://example.com" } };
    const result = await pi.handlers.get("tool_call")?.(event, context as never);

    expect(result).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledTimes(2);
    expect(event.input.command).toContain("PI_SRT_HELPER_INPUT_B64=");
    expect(extractHelperInput(event.input.command).runtimeConfig.network).toEqual(
      expect.objectContaining({ allowedDomains: ["example.com"] }),
    );
  });

  it("does not reuse allow-once sandbox approval for a later invocation", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        bash: {
          "echo ok https://example.com": "allow",
        },
      },
      network: { enabled: true, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow once", "Allow once"] });
    const handler = pi.handlers.get("tool_call")!;
    const firstEvent = { toolName: "bash", input: { command: "echo ok https://example.com" } };
    const secondEvent = { toolName: "bash", input: { command: "echo ok https://example.com" } };

    await handler(firstEvent, context as never);
    await handler(secondEvent, context as never);

    expect(context.ui.select).toHaveBeenCalledTimes(2);
  });

  it("does not persist sandbox network approval into domain policy", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        bash: {
          "echo ok https://example.com": "allow",
        },
      },
      network: { enabled: true, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow globally"] });
    const event = { toolName: "bash", input: { command: "echo ok https://example.com" } };
    await pi.handlers.get("tool_call")?.(event, context as never);

    const sandboxOptions = (context.ui.select as ReturnType<typeof vi.fn>).mock.calls[0]?.[1] as string[];
    expect(sandboxOptions).toContain("Allow globally");
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8"))).toMatchObject({
      network: { allowedDomains: [] },
      sandbox: { network: true },
    });
  });

  it("blocks tool calls without UI when sandbox approval is required", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        bash: {
          "curl https://example.com": "allow",
        },
      },
      network: { enabled: true, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const event = { toolName: "bash", input: { command: "curl https://example.com" } };
    const result = await pi.handlers.get("tool_call")?.(event, context as never);

    expect(result).toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
    expect(event.input.command).toBe("curl https://example.com");
  });

  it("asks for sandbox approval for user bash network commands", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        bash: {
          "echo ok https://example.com": "allow",
        },
      },
      network: { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, {
      hasUI: true,
      choices: ["Allow once", "Allow once", "Allow once", "Allow once"],
    });
    const handler = pi.handlers.get("user_bash")!;
    const firstResult = await handler(
      { command: "echo ok https://example.com", cwd: projectDir },
      context as never,
    );
    const secondResult = await handler(
      { command: "echo ok https://example.com", cwd: projectDir },
      context as never,
    );

    expect(firstResult).toHaveProperty("operations");
    expect(secondResult).toHaveProperty("operations");
    expect(context.ui.select).toHaveBeenCalledTimes(4);
  });

  it("fails closed when user bash sandbox prompting throws", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await mkdtemp(path.join(homedir(), ".pi-permission-outside-"));
    tempPaths.push(outsideDir);
    const outsideFile = path.join(outsideDir, "secret.txt");
    await writeFile(outsideFile, "secret", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true });
    context.ui.select = vi.fn(async () => {
      throw new Error("prompt unavailable");
    });

    const result = await pi.handlers.get("user_bash")?.(
      { command: `cat ${outsideFile}`, cwd: projectDir },
      context as never,
    );

    expect(result).toMatchObject({
      result: {
        exitCode: 1,
        output: expect.stringContaining("command blocked"),
      },
    });
  });

  it("does not re-prompt after approving an external masked file", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await makeTempDir("pi-permission-outside-");
    const outsideFile = path.join(outsideDir, ".env");
    await writeFile(outsideFile, "SECRET=test\n", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: ["**/.env"],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, {
      hasUI: true,
      choices: ["Allow once"],
    });
    const result = await pi.handlers.get("user_bash")?.(
      { command: `cat ${outsideFile}`, cwd: projectDir },
      context as never,
    );

    expect(result).toHaveProperty("operations");
    expect(context.ui.select).toHaveBeenCalledTimes(1);
  });

  it("grants one-shot write access only to external output targets", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await mkdtemp(path.join(homedir(), ".pi-permission-outside-write-"));
    tempPaths.push(outsideDir);
    const inputFile = path.join(outsideDir, "input.txt");
    const outputFile = path.join(outsideDir, "output.txt");
    await writeFile(inputFile, "source", "utf8");
    await writeFile(outputFile, "before", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        external_directory: { "*": "allow" },
      },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow once", "Allow once"] });
    const command = "cat " + inputFile + " > " + outputFile;
    const event = { toolName: "bash", input: { command } };
    const result = await pi.handlers.get("tool_call")?.(event, context as never);

    expect(result).toBeUndefined();
    const helper = extractHelperInput(event.input.command);
    expect(helper.runtimeConfig.filesystem.allowWrite).toContain(outputFile);
    expect(helper.runtimeConfig.filesystem.allowWrite).not.toContain(inputFile);
    const inputIsReadable = helper.runtimeConfig.filesystem.allowRead.some((allowedPath: string) => {
      const relative = path.relative(allowedPath, inputFile);
      return relative === "" || (
        relative !== ".." &&
        !relative.startsWith(".." + path.sep) &&
        !path.isAbsolute(relative)
      );
    });
    expect(inputIsReadable).toBe(true);
    expect(await readFile(path.join(agentDir, "permissions.json"), "utf8")).not.toContain(outputFile);
  });

  it("grants parent read-write access for a missing external output target", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await mkdtemp(path.join(homedir(), ".pi-permission-outside-write-"));
    tempPaths.push(outsideDir);
    const inputFile = path.join(outsideDir, "input.txt");
    const outputFile = path.join(outsideDir, "new", "output.txt");
    await writeFile(inputFile, "source", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        external_directory: { "*": "allow" },
      },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
    const event = { toolName: "bash", input: { command: "cat " + inputFile + " > " + outputFile } };
    const result = await pi.handlers.get("tool_call")?.(event, context as never);

    expect(result).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledTimes(1);
    expect(context.ui.select.mock.calls[0]?.[0]).toContain(outsideDir + " (directory)");
    expect(context.ui.select.mock.calls[0]?.[0]).toContain("read-write access");
    expect(extractHelperInput(event.input.command).runtimeConfig.filesystem.allowWrite).toContain(outsideDir);
  });

  it("requests read-write approval for user bash output targets", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await mkdtemp(path.join(homedir(), ".pi-permission-outside-write-"));
    tempPaths.push(outsideDir);
    const outsideFile = path.join(outsideDir, "existing.txt");
    await writeFile(outsideFile, "before", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
    const result = await pi.handlers.get("user_bash")?.(
      { command: "echo updated > " + outsideFile, cwd: projectDir },
      context as never,
    );

    expect(result).toHaveProperty("operations");
    expect(context.ui.select).toHaveBeenCalledTimes(1);
    expect(context.ui.select.mock.calls[0]?.[0]).toContain("read-write access");
    expect(context.ui.select.mock.calls[0]?.[0]).toContain(outsideFile);
  });

  it("grants parent read-write access for a missing user bash output target", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const outsideDir = await mkdtemp(path.join(homedir(), ".pi-permission-outside-write-"));
    tempPaths.push(outsideDir);
    const inputFile = path.join(outsideDir, "input.txt");
    const outputFile = path.join(outsideDir, "new", "output.txt");
    await writeFile(inputFile, "source", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
    const result = await pi.handlers.get("user_bash")?.(
      { command: "cat " + inputFile + " > " + outputFile, cwd: projectDir },
      context as never,
    );

    expect(result).toHaveProperty("operations");
    expect(context.ui.select).toHaveBeenCalledTimes(1);
    expect(context.ui.select.mock.calls[0]?.[0]).toContain(outsideDir + " (directory)");
    expect(context.ui.select.mock.calls[0]?.[0]).toContain("read-write access");
  });

  it.each(["tool_call", "user_bash"])("rejects unsupported output redirect quoting through %s", async (surface) => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        external_directory: { "*": "allow" },
      },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true });
    const outputFile = path.join(homedir(), ".pi-unsupported-output.txt");
    const command = "echo value > $'" + outputFile + "'";
    const result = surface === "tool_call"
      ? await pi.handlers.get("tool_call")?.(
          { toolName: "bash", input: { command } },
          context as never,
        )
      : await pi.handlers.get("user_bash")?.(
          { command, cwd: projectDir },
          context as never,
        );

    expect(JSON.stringify(result)).toContain("Unsupported Bash output redirect target quoting.");
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("blocks user bash when requested path approval is invalid", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const result = await pi.handlers.get("user_bash")?.(
      { command: `cat ${homedir()}`, cwd: projectDir },
      createContext(projectDir, { hasUI: true }) as never,
    );

    expect(result).toMatchObject({
      result: {
        exitCode: 1,
        output: expect.stringContaining("command blocked"),
      },
    });
  });

  it("reports protected socket refusal for invalid external paths", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        external_directory: { "*": "allow" },
      },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const result = await pi.handlers.get("tool_call")?.(
      { toolName: "bash", input: { command: "ls -ld /var/run" } },
      createContext(projectDir, { hasUI: true, choices: ["Allow once"] }) as never,
    );

    expect(result).toMatchObject({
      block: true,
      reason: expect.stringContaining("protected socket location"),
    });
  });

  it.skipIf(!canSimulateReadOnlyDirectory)("blocks user bash when persistent sandbox approval cannot be saved", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      network: { enabled: true, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });
    const permissionsPath = path.join(agentDir, "permissions.json");
    const realConfigPath = path.join(agentDir, "real-permissions.json");
    await rename(permissionsPath, realConfigPath);
    await symlink(realConfigPath, permissionsPath);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    await chmod(agentDir, 0o500);
    try {
      const context = createContext(projectDir, { hasUI: true, choices: ["Allow globally"] });
      const result = await pi.handlers.get("user_bash")?.(
        { command: "curl https://example.com", cwd: projectDir },
        context as never,
      );

      expect(result).toMatchObject({ result: { exitCode: 1, output: expect.stringContaining("failed to persist") } });
    } finally {
      await chmod(agentDir, 0o700);
    }
  });

  it("blocks user bash before wrapping when sandbox approval is denied", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      network: { enabled: true, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Deny"] });
    const result = await pi.handlers.get("user_bash")?.(
      { command: "curl https://example.com", cwd: projectDir },
      context as never,
    );

    expect(result).toMatchObject({ result: { exitCode: 1 } });
    expect(result).toMatchObject({ result: { output: expect.stringContaining("User denied") } });
    expect(context.ui.select).toHaveBeenCalledTimes(1);
  });

  it("blocks user bash without UI when sandbox approval is required", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      network: { enabled: true, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const result = await pi.handlers.get("user_bash")?.(
      { command: "curl https://example.com", cwd: projectDir },
      context as never,
    );

    expect(result).toMatchObject({ result: { exitCode: 1 } });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("keeps explicit domain denies ahead of sandbox prompts", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "deny",
        bash: { "echo ok https://example.com": "allow" },
      },
      network: { enabled: true, unknownDomains: "ask", allowedDomains: [], deniedDomains: ["example.com"] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: [],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
    const event = { toolName: "bash", input: { command: "echo ok https://example.com" } };
    const result = await pi.handlers.get("tool_call")?.(event, context as never);

    expect(result).toMatchObject({
      block: true,
      reason: expect.stringContaining("Domain gate blocked"),
    });
    expect(context.ui.select).not.toHaveBeenCalled();
    expect(event.input.command).toBe("echo ok https://example.com");

    const userResult = await pi.handlers.get("user_bash")?.(
      { command: "echo ok https://example.com", cwd: projectDir },
      context as never,
    );
    expect(userResult).toMatchObject({
      result: { output: expect.stringContaining("Domain gate blocked"), exitCode: 1 },
    });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

});
