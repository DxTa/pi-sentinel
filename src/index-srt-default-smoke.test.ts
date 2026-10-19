import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { chmod, mkdir, mkdtemp, realpath, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import piPermissionSystemExtension from "./index.ts";
import { resolveDockerSocketPaths } from "./sandbox/docker-socket.js";
import { YOLO_AUTO_BUILD_ID } from "./yolo-auto-build";
import { YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema";
import type { YoloAutoHeads } from "./yolo-auto-policy";
import { YoloAutoWorkerServer } from "./yolo-auto-worker";

const mockDockerSocketPaths = vi.hoisted(() => vi.fn((): string[] => []));
vi.mock("./sandbox/docker-socket.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./sandbox/docker-socket.js")>();
  return { ...actual, resolveDockerSocketPaths: mockDockerSocketPaths };
});

const tempPaths: string[] = [];
let originalPath: string | undefined;
let originalHome: string | undefined;
let originalSshAuthSock: string | undefined;
let fakeSrtBin = "";
const canSimulateReadOnlyDirectory = process.platform !== "win32" && process.getuid?.() !== 0;

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

async function makeSyntheticHome(): Promise<string> {
  const home = await makeTempDir("pi-synthetic-home-");
  process.env.HOME = home;
  return home;
}

async function makeSyntheticAwsCredentials(): Promise<string> {
  const home = await makeSyntheticHome();
  const credentials = path.join(home, ".aws", "credentials");
  await mkdir(path.dirname(credentials), { recursive: true });
  await writeFile(credentials, "[default]\naws_access_key_id = synthetic\n", "utf8");
  return credentials;
}

beforeEach(async () => {
  mockDockerSocketPaths.mockReturnValue([]);
  // Tool-call smoke tests only build wrapper operations; the stub is never executed.
  originalPath = process.env.PATH;
  originalHome = process.env.HOME;
  originalSshAuthSock = process.env.SSH_AUTH_SOCK;
  fakeSrtBin = await mkdtemp(path.join(tmpdir(), "pi-srt-test-deps-"));
  tempPaths.push(fakeSrtBin);
  const fakeSocat = path.join(fakeSrtBin, "socat");
  await writeFile(fakeSocat, "#!/bin/sh\nexit 97\n", "utf8");
  await chmod(fakeSocat, 0o755);
  process.env.PATH = `${fakeSrtBin}${path.delimiter}${originalPath ?? ""}`;
});

afterEach(async () => {
  delete process.env.PI_CODING_AGENT_DIR;
  delete process.env.PI_SENTINEL_YOLO_AUTO_SOCKET;
  if (originalPath === undefined) delete process.env.PATH;
  else process.env.PATH = originalPath;
  originalPath = undefined;
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  originalHome = undefined;
  if (originalSshAuthSock === undefined) delete process.env.SSH_AUTH_SOCK;
  else process.env.SSH_AUTH_SOCK = originalSshAuthSock;
  originalSshAuthSock = undefined;
  fakeSrtBin = "";
  mockDockerSocketPaths.mockReturnValue([]);
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

function createContext(cwd: string, options: { hasUI?: boolean; choices?: Array<string | undefined> } = {}) {
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

async function setupPushFallback(overrides: Record<string, unknown> = {}) {
  const agentDir = await makeTempDir("pi-push-fallback-agent-");
  const projectDir = await makeTempDir("pi-push-fallback-project-");
  await makeSyntheticHome();
  process.env.SSH_AUTH_SOCK = "";
  process.env.PI_CODING_AGENT_DIR = agentDir;
  await writeExtensionConfig(agentDir, {
    permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
    ...overrides,
  });
  const pi = createFakePi();
  piPermissionSystemExtension(pi as never);
  const command = "git -C . push https://example.test/repo.git main";
  let callId = 0;
  const run = async (ctx: ReturnType<typeof createContext>, rawCommand = command) => {
    const event = { toolName: "bash", toolCallId: `push-${++callId}`, input: { command: rawCommand } };
    const result = await pi.handlers.get("tool_call")!(event, ctx);
    return { event, result };
  };
  const fail = (event: { toolName: string; toolCallId: string; input: { command: string } }, ctx: ReturnType<typeof createContext>, output = "socat[123] E proxy_connect: connection closed by proxy") =>
    pi.handlers.get("tool_result")!({
      ...event, content: [{ type: "text", text: output }], isError: true,
    }, ctx);
  return { agentDir, projectDir, pi, command, run, fail };
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
  it("offers one-time host execution only on the next identical push after SRT egress failure", async () => {
    const agentDir = await makeTempDir("pi-push-fallback-agent-");
    const projectDir = await makeTempDir("pi-push-fallback-project-");
    await makeSyntheticHome();
    process.env.SSH_AUTH_SOCK = "";
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
    });
    const configBefore = await readFile(path.join(agentDir, "permissions.json"), "utf8");
    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const command = "git -C . push https://example.test/repo.git main";
    const context = createContext(projectDir, { hasUI: true, choices: ["Yes", "Yes", "Allow once", "Yes"] });
    const call = pi.handlers.get("tool_call")!;
    const first = { toolName: "bash", toolCallId: "push-1", input: { command } };
    await expect(call(first, context)).resolves.toBeUndefined();
    expect(first.input.command).not.toBe(command);
    expect(context.ui.select).toHaveBeenCalledOnce();

    await pi.handlers.get("tool_result")!({
      ...first,
      content: [{ type: "text", text: "socat[123] E proxy_connect: connection closed by proxy" }],
      isError: true,
    }, context);
    expect(context.ui.select).toHaveBeenCalledOnce();

    const next = { toolName: "bash", toolCallId: "push-2", input: { command } };
    await expect(call(next, context)).resolves.toBeUndefined();
    expect(next.input.command).toBe(command);
    expect(context.ui.select).toHaveBeenCalledTimes(3);
    expect(context.ui.select.mock.calls[2][0]).toContain("outside sandbox protections");
    expect(context.ui.select.mock.calls[2][0]).toContain(command);
    expect(context.ui.select.mock.calls[2][1]).toEqual(["Allow once", "Deny"]);

    const third = { toolName: "bash", toolCallId: "push-3", input: { command } };
    await expect(call(third, context)).resolves.toBeUndefined();
    expect(third.input.command).not.toBe(command);
    expect(context.ui.select).toHaveBeenCalledTimes(4);
    for (const index of [0, 1, 3]) {
      expect(context.ui.select.mock.calls[index][1]).toEqual(["Yes", "No", "No, provide reason"]);
    }
    expect(await readFile(path.join(agentDir, "permissions.json"), "utf8")).toBe(configBefore);
  });

  it("offers one-time host execution for a failed plain SSH Git push despite the implicit-auth SRT requirement", async () => {
    const fixture = await setupPushFallback();
    const sshDir = path.join(process.env.HOME!, ".ssh");
    await mkdir(sshDir, { recursive: true });
    await writeFile(path.join(sshDir, "id_ed25519"), "synthetic-key", "utf8");
    await mkdir(path.join(fixture.projectDir, ".git"));
    await writeFile(path.join(fixture.projectDir, ".git", "config"), '[remote "origin"]\nurl = git@example.test:repo.git\n', "utf8");
    const command = "git push origin main";
    const ctx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes", "Allow once", "Yes", "Allow once", "Allow once"] });
    const first = await fixture.run(ctx, command);
    expect(first.result).toBeUndefined();
    expect(first.event.input.command).not.toBe(command);
    await fixture.fail(first.event, ctx);
    const next = await fixture.run(ctx, command);
    expect(next.result).toBeUndefined();
    expect(next.event.input.command).toBe(command);
    expect(ctx.ui.select.mock.calls.at(-1)?.[1]).toEqual(["Allow once", "Deny"]);
  });

  it.each(["Deny", undefined, "Allow for session"])(
    "blocks one-time host execution when the fallback choice is %s and consumes the failure",
    async (choice) => {
      const fixture = await setupPushFallback();
      const firstCtx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes"] });
      const first = await fixture.run(firstCtx);
      expect(first.result).toBeUndefined();
      await fixture.fail(first.event, firstCtx);
      const ctx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes", choice, "Yes"] });
      const denied = await fixture.run(ctx);
      expect(denied.result).toMatchObject({ block: true, reason: expect.stringContaining("host execution denied") });
      expect(denied.event.input.command).toBe(fixture.command);
      const next = await fixture.run(ctx);
      expect(next.result).toBeUndefined();
      expect(next.event.input.command).not.toBe(fixture.command);
      expect(ctx.ui.select.mock.calls.filter(([, options]) => options.length === 2)).toHaveLength(1);
    },
  );

  it("keeps push failures scoped to the exact command and working directory", async () => {
    const fixture = await setupPushFallback();
    const ctx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes", "Yes", "Allow once"] });
    const first = await fixture.run(ctx);
    await fixture.fail(first.event, ctx);
    const changed = await fixture.run(ctx, `${fixture.command} --dry-run`);
    expect(changed.result).toBeUndefined();
    expect(changed.event.input.command).not.toBe(`${fixture.command} --dry-run`);
    expect(ctx.ui.select).toHaveBeenCalledTimes(2);
    const otherDir = await makeTempDir("pi-push-other-project-");
    const otherCtx = createContext(otherDir, { hasUI: true, choices: ["Yes"] });
    const other = await fixture.run(otherCtx);
    expect(other.result).toBeUndefined();
    expect(other.event.input.command).not.toBe(fixture.command);
    expect(otherCtx.ui.select).toHaveBeenCalledOnce();
  });

  it("never offers host execution without a UI even after an SRT push failure", async () => {
    const fixture = await setupPushFallback();
    const firstCtx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes"] });
    const first = await fixture.run(firstCtx);
    await fixture.fail(first.event, firstCtx);
    const ctx = createContext(fixture.projectDir);
    const denied = await fixture.run(ctx);
    expect(denied.result).toMatchObject({ block: true });
    expect(ctx.ui.select).not.toHaveBeenCalled();
    expect(denied.event.input.command).toBe(fixture.command);
  });

  it.each([false, true])("clears push fallback at session start including late results (late=%s)", async (late) => {
    const fixture = await setupPushFallback();
    const ctx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes", "Yes"] });
    const first = await fixture.run(ctx);
    if (!late) await fixture.fail(first.event, ctx);
    await fixture.pi.handlers.get("session_start")!({}, ctx);
    if (late) await fixture.fail(first.event, ctx);
    const next = await fixture.run(ctx);
    expect(next.result).toBeUndefined();
    expect(next.event.input.command).not.toBe(fixture.command);
    expect(ctx.ui.select.mock.calls.every(([, options]) => options.length === 3)).toBe(true);
  });

  it("rejects host execution approval if the session changes while its prompt is open", async () => {
    const fixture = await setupPushFallback();
    const ctx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes", "Yes"] });
    const first = await fixture.run(ctx);
    await fixture.fail(first.event, ctx);
    const select = ctx.ui.select;
    let selections = 0;
    select.mockImplementation(async () => {
      if (++selections === 1) return "Yes";
      await fixture.pi.handlers.get("session_start")!({}, ctx);
      return "Allow once";
    });
    const next = await fixture.run(ctx);
    expect(next.result).toMatchObject({ block: true, reason: expect.stringContaining("host execution denied") });
    expect(next.event.input.command).toBe(fixture.command);
  });

  it("preserves explicit push denies before offering host execution", async () => {
    const fixture = await setupPushFallback();
    const ctx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes"] });
    const first = await fixture.run(ctx);
    await fixture.fail(first.event, ctx);
    await writeExtensionConfig(fixture.agentDir, { permission: { "*": "allow", bash: { "git *": "deny" } } });
    await fixture.pi.handlers.get("resources_discover")!({ reason: "reload" }, ctx);
    ctx.ui.select.mockClear();
    const denied = await fixture.run(ctx);
    expect(denied.result).toMatchObject({ block: true });
    expect(ctx.ui.select).not.toHaveBeenCalled();
  });

  it.each(["ordinary network failure", "untracked proxy output", "successful proxy output"])(
    "does not offer host execution after %s",
    async (failure) => {
      const fixture = await setupPushFallback();
      const ctx = createContext(fixture.projectDir, { hasUI: true, choices: ["Yes", "Yes"] });
      const first = await fixture.run(ctx);
      await fixture.pi.handlers.get("tool_result")!({
        ...first.event,
        toolCallId: failure === "untracked proxy output" ? "untracked" : first.event.toolCallId,
        content: [{ type: "text", text: failure === "ordinary network failure"
          ? "Connection refused"
          : "socat[123] E proxy_connect: connection closed by proxy" }],
        isError: failure !== "successful proxy output",
      }, ctx);
      const next = await fixture.run(ctx);
      expect(next.result).toBeUndefined();
      expect(next.event.input.command).not.toBe(fixture.command);
      expect(ctx.ui.select).toHaveBeenCalledTimes(2);
    },
  );

  it("masks dotenv read results but leaves .env.example unchanged", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const toolResult = pi.handlers.get("tool_result");
    const envPath = path.join(projectDir, ".env");
    await writeFile(envPath, "TOKEN=secret-value\nMODE=dev", "utf8");
    const result = await toolResult?.({
      toolCallId: "env-read",
      toolName: "read",
      input: { path: envPath },
      content: [{ type: "text", text: "TOKEN=secret-value\nMODE=dev" }],
      isError: false,
    }, createContext(projectDir));

    expect(result).toEqual({
      content: [{ type: "text", text: "TOKEN=****\nMODE=****" }],
    });

    const throwingMetadata = new Proxy({}, {
      get(_target, property) {
        if (property === "truncation") throw new Error("metadata access failed");
        return undefined;
      },
    });
    const exceptionResult = await toolResult?.({
      toolCallId: "env-read-mask-exception",
      toolName: "read",
      input: { path: envPath },
      content: [{ type: "text", text: "TOKEN=secret-value\nMODE=dev" }],
      details: throwingMetadata,
      isError: false,
    }, createContext(projectDir));
    expect(exceptionResult).toEqual({ content: [{ type: "text", text: "****" }] });

    const encodedEnvUrl = pathToFileURL(envPath).href.replace(".env", "%2Eenv");
    const encodedPathResult = await toolResult?.({
      toolCallId: "env-read-file-url",
      toolName: "read",
      input: { path: encodedEnvUrl },
      content: [{ type: "text", text: "TOKEN=secret-value\nMODE=dev" }],
      isError: false,
    }, createContext(projectDir));
    expect(encodedPathResult).toEqual({
      content: [{ type: "text", text: "TOKEN=****\nMODE=****" }],
    });
    const imageResult = await toolResult?.({
      toolCallId: "env-read-image",
      toolName: "read",
      input: { path: envPath },
      content: [{ type: "image", data: "raw-image-secret", mimeType: "image/png" }],
      isError: false,
    }, createContext(projectDir));
    expect(imageResult).toEqual({
      content: [{ type: "text", text: "****" }],
    });

    const exampleResult = await toolResult?.({
      toolCallId: "env-example-read",
      toolName: "read",
      input: { path: path.join(projectDir, ".env.example") },
      content: [{ type: "text", text: "TOKEN=placeholder-value" }],
      isError: false,
    }, createContext(projectDir));
    expect(exampleResult).toBeUndefined();

    const mixedCaseExamplePath = path.join(projectDir, ".ENV.EXAMPLE");
    await writeFile(mixedCaseExamplePath, "TOKEN=placeholder-value", "utf8");
    const mixedCaseExampleResult = await toolResult?.({
      toolCallId: "env-example-case-read",
      toolName: "read",
      input: { path: mixedCaseExamplePath },
      content: [{ type: "text", text: "TOKEN=placeholder-value" }],
      isError: false,
    }, createContext(projectDir));
    expect(mixedCaseExampleResult).toBeUndefined();

    const mixedCaseEnvPath = path.join(projectDir, ".Env.local");
    const dotenvAliasPath = path.join(projectDir, "plain-config");
    await writeFile(mixedCaseEnvPath, "TOKEN=case-sensitive-secret", "utf8");
    await symlink(mixedCaseEnvPath, dotenvAliasPath);
    for (const requestPath of [mixedCaseEnvPath, `@${mixedCaseEnvPath}`, dotenvAliasPath]) {
      const caseResult = await toolResult?.({
        toolCallId: `env-read-${requestPath}`,
        toolName: "read",
        input: { path: requestPath },
        content: [{ type: "text", text: "TOKEN=case-sensitive-secret" }],
        isError: false,
      }, createContext(projectDir));
      expect(caseResult).toEqual({
        content: [{ type: "text", text: "TOKEN=****" }],
      });
    }

    const trailingSpaceAlias = path.join(projectDir, "notes ");
    const curlyQuoteAlias = path.join(projectDir, "it’s");
    await symlink(envPath, trailingSpaceAlias);
    await symlink(envPath, curlyQuoteAlias);
    const trailingSpaceResult = await toolResult?.({
      toolCallId: "env-read-trailing-space-alias",
      toolName: "read",
      input: { path: trailingSpaceAlias },
      content: [{ type: "text", text: "TOKEN=secret-value\nMODE=dev" }],
      isError: false,
    }, createContext(projectDir));
    expect(trailingSpaceResult).toEqual({
      content: [{ type: "text", text: "TOKEN=****\nMODE=****" }],
    });

    const curlyQuoteResult = await toolResult?.({
      toolCallId: "env-read-curly-quote-alias",
      toolName: "read",
      input: { path: path.join(projectDir, "it's") },
      content: [{ type: "text", text: "TOKEN=secret-value\nMODE=dev" }],
      isError: false,
    }, createContext(projectDir));
    expect(curlyQuoteResult).toEqual({ content: [{ type: "text", text: "TOKEN=****\nMODE=****" }] });

    await writeFile(envPath, 'TOKEN="first-part\nsecret-middle\nlast-part"\n', "utf8");
    const partialResult = await toolResult?.({
      toolCallId: "env-read-offset",
      toolName: "read",
      input: { path: ".env", offset: 2, limit: 1 },
      content: [{
        type: "text",
        text: "secret-middle\n\n[2 more lines in file. Use offset=3 to continue.]",
      }],
      isError: false,
    }, createContext(projectDir));
    expect(partialResult).toEqual({
      content: [{
        type: "text",
        text: "****\n\n[2 more lines in file. Use offset=3 to continue.]",
      }],
    });

    const truncatedResult = await toolResult?.({
      toolCallId: "env-read-truncated",
      toolName: "read",
      input: { path: envPath },
      content: [{
        type: "text",
        text: 'TOKEN="first-part\nsecret-middle\n\n[Showing lines 1-2 of 4 (50.0KB limit). Use offset=3 to continue.]',
      }],
      details: {
        truncation: {
          content: 'TOKEN="first-part\nsecret-middle',
          truncated: true,
          truncatedBy: "lines",
          totalLines: 4,
          totalBytes: 50,
          outputLines: 2,
          outputBytes: 30,
          lastLinePartial: false,
          firstLineExceedsLimit: false,
          maxLines: 2,
          maxBytes: 50 * 1024,
        },
      },
      isError: false,
    }, createContext(projectDir));
    expect(truncatedResult).toEqual({
      content: [{
        type: "text",
        text: 'TOKEN=****\n****\n\n[Showing lines 1-2 of 4 (50.0KB limit). Use offset=3 to continue.]',
      }],
      details: {
        truncation: {
          content: "TOKEN=****\n****",
          truncated: true,
          truncatedBy: "lines",
          totalLines: 4,
          totalBytes: 50,
          outputLines: 2,
          outputBytes: 30,
          lastLinePartial: false,
          firstLineExceedsLimit: false,
          maxLines: 2,
          maxBytes: 50 * 1024,
        },
      },
    });

    const unavailableSourceResult = await toolResult?.({
      toolCallId: "env-read-source-unavailable",
      toolName: "read",
      input: { path: path.join(projectDir, ".env-raced") },
      content: [{ type: "text", text: "TOKEN=secret-value" }],
      details: { truncation: { content: "TOKEN=secret-value" } },
      isError: false,
    }, createContext(projectDir));
    expect(unavailableSourceResult).toEqual({
      content: [{ type: "text", text: "****" }],
      details: { truncation: { content: "****" } },
    });
  });

  it.each(["manual", "yolo", "yolo-auto"] as const)(
    "auto-allows protected credential reads and fully redacts output in %s mode",
    async (mode) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        mode,
        permission: { bash: { "*": "allow" } },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: { "offline-dev": { network: false, env: { allow: [], deny: [] }, maskedPaths: [] } },
      },
    });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir);
      const redacted = { content: [{ type: "text", text: "****" }] };

      for (const secretPath of [path.join(homedir(), ".ssh", "id_ed25519"), path.join(homedir(), ".config", "gh", "hosts.yml")]) {
        expect(await pi.handlers.get("tool_result")?.({
          toolCallId: "t-protected-read",
          toolName: "read",
          input: { path: secretPath },
          content: [{ type: "text", text: "super-secret-token" }],
          isError: false,
        }, context as never)).toEqual(redacted);
      }

      const bashPath = path.join(homedir(), ".config", "gh", "hosts.yml");
      const event = { toolName: "bash", toolCallId: "t-protected-bash", input: { command: `cat ${bashPath}` } };
      expect(await pi.handlers.get("tool_call")?.(event, context as never)).toBeUndefined();
      expect(context.ui.select).not.toHaveBeenCalled();
      expect(await pi.handlers.get("tool_result")?.({
        toolCallId: "t-protected-bash",
        toolName: "bash",
        input: event.input,
        content: [{ type: "text", text: "super-secret-token" }],
        isError: false,
      }, context as never)).toEqual(redacted);
      const errorEvent = {
        toolName: "bash",
        toolCallId: "t-protected-bash-error",
        input: { command: `cat ${bashPath}` },
      };
      expect(await pi.handlers.get("tool_call")?.(errorEvent, context as never)).toBeUndefined();
      expect(await pi.handlers.get("tool_result")?.({
        toolCallId: errorEvent.toolCallId,
        toolName: "bash",
        input: errorEvent.input,
        content: [{ type: "text", text: "error: super-secret-token" }],
        details: { truncation: { content: "error: super-secret-token" } },
        isError: true,
      }, context as never)).toEqual({
        content: [{ type: "text", text: "****" }],
        details: { truncation: { content: "****" } },
      });
    },
  );

  it.each(["manual", "yolo", "yolo-auto"] as const)(
    "blocks protected credential reads outside SRT in %s mode",
    async (mode) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        mode,
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const result = await pi.handlers.get("tool_call")?.(
        { toolName: "bash", input: { command: "cat ~/.aws/credentials" } },
        createContext(projectDir) as never,
      );
      expect(result).toMatchObject({ block: true, reason: expect.stringContaining("SRT read-only boundary") });
    },
  );

  it("routes dotenv access through SRT despite host bypass and still blocks implicit Git auth", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env.local");
    await mkdir(path.join(projectDir, ".git"));
    await writeFile(envPath, "TOKEN=synthetic-secret", "utf8");
    await writeFile(path.join(projectDir, ".git", "config"), '[remote "origin"]\nurl = git@example.test:repo.git\n', "utf8");
    await makeSyntheticHome();
    process.env.SSH_AUTH_SOCK = "";
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      mode: "yolo",
      permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "online-dev",
        bypassCommands: [`docker run --env-file ${envPath} alpine:latest`],
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const toolCall = pi.handlers.get("tool_call");
    const context = createContext(projectDir);
    mockDockerSocketPaths.mockReturnValue([path.join(projectDir, "docker.sock")]);
    const dockerEvent = {
      toolName: "bash",
      toolCallId: "dotenv-host-bypass",
      input: { command: `docker run --env-file ${envPath} alpine:latest` },
    };
    await expect(toolCall?.(dockerEvent, context as never)).resolves.toBeUndefined();
    const dockerHelperInput = extractHelperInput(dockerEvent.input.command);
    const approvedEnvPath = await realpath(envPath);
    expect(dockerHelperInput.runtimeConfig.filesystem.allowRead).toContain(approvedEnvPath);
    expect(dockerHelperInput.runtimeConfig.filesystem.denyWrite).toContain(approvedEnvPath);
    await expect(toolCall?.(
      { toolName: "bash", input: { command: "git push" } },
      context as never,
    )).resolves.toMatchObject({ block: true, reason: expect.stringContaining("SRT read-only boundary") });
  });

  it("routes user Bash dotenv reads through SRT despite wildcard host bypass", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env.local");
    await writeFile(envPath, "TOKEN=synthetic-secret\n", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const result = await pi.handlers.get("user_bash")?.(
      { command: `cat ${envPath}`, cwd: projectDir },
      context as never,
    );

    expect(result).toHaveProperty("operations");
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it.each(["tool_call", "user_bash"] as const)(
    "blocks protected paths from a session-approved GPG bypass in %s",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      const envPath = path.join(projectDir, ".env.local");
      await writeFile(envPath, "TOKEN=synthetic-secret\n", "utf8");
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        mode: "manual",
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev" },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir, { hasUI: true, choices: ["Allow for session"] });
      await expect(pi.handlers.get("tool_call")?.(
        { toolName: "bash", input: { command: "gpg --detach-sign artifact" } },
        context as never,
      )).resolves.toBeUndefined();

      const command = `cat ${envPath}; gpg --detach-sign artifact`;
      const result = surface === "tool_call"
        ? await pi.handlers.get("tool_call")?.(
            { toolName: "bash", toolCallId: "protected-gpg-bypass", input: { command } },
            context as never,
          )
        : await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);

      if (surface === "tool_call") {
        expect(result).toMatchObject({ block: true, reason: expect.stringContaining("protected") });
      } else {
        expect(result).toMatchObject({
          result: { exitCode: 1, output: expect.stringContaining("protected") },
        });
      }
    },
  );

  it.each([
    { mode: "manual", surface: "user_bash" },
    { mode: "yolo", surface: "tool_call" },
    { mode: "yolo", surface: "user_bash" },
    { mode: "yolo-auto", surface: "user_bash" },
  ] as const)(
    "blocks shell-quoted protected paths from a GPG bypass in $mode mode through $surface",
    async ({ mode, surface }) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      const envPath = path.join(projectDir, ".env.local");
      await writeFile(envPath, "TOKEN=synthetic-secret\n", "utf8");
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        mode,
        permission: {
          "*": "allow",
          bash: { "*": "allow" },
          path: { "*": "allow" },
          external_directory: { "*": "allow" },
        },
        sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev" },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir, { hasUI: true, choices: ["Allow for session"] });
      await expect(pi.handlers.get("tool_call")?.(
        { toolName: "bash", input: { command: "gpg --detach-sign artifact" } },
        context as never,
      )).resolves.toBeUndefined();

      const quotedEnvPath = envPath.replace(".env.local", ".en'v.local'");
      const command = `cat ${quotedEnvPath}; gpg --detach-sign artifact`;
      const result = surface === "tool_call"
        ? await pi.handlers.get("tool_call")?.(
            { toolName: "bash", toolCallId: `quoted-gpg-bypass-${mode}`, input: { command } },
            context as never,
          )
        : await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);

      if (surface === "tool_call") {
        expect(result).toMatchObject({ block: true, reason: expect.stringContaining("protected") });
      } else {
        expect(result).toMatchObject({
          result: { exitCode: 1, output: expect.stringContaining("protected") },
        });
      }
    },
  );

  it.skipIf(process.platform !== "linux")("blocks credential consumption when SRT dependencies are unavailable", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const noSocatBin = await makeTempDir("pi-srt-no-socat-");
    for (const dependency of ["rg", "bwrap"]) {
      const stub = path.join(noSocatBin, dependency);
      await writeFile(stub, "#!/bin/sh\nexit 97\n", "utf8");
      await chmod(stub, 0o755);
    }
    process.env.PATH = noSocatBin;
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev" },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const result = await pi.handlers.get("tool_call")?.(
      { toolName: "bash", toolCallId: "missing-srt-auth", input: { command: "cat ~/.aws/credentials" } },
      createContext(projectDir) as never,
    );
    expect(result).toMatchObject({ block: true, reason: expect.stringContaining("Missing SRT runtime dependencies: socat") });
  });

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

  it("routes default-context Docker ps through SRT despite wildcard host bypass", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const socketPath = path.join(projectDir, "docker.sock");
    mockDockerSocketPaths.mockReturnValue([socketPath]);
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const event = {
      toolName: "bash",
      toolCallId: "docker-default-context",
      input: { command: "docker ps --format 'table {{.Names}}\\t{{.Status}}'" },
    };
    await expect(pi.handlers.get("tool_call")?.(event, createContext(projectDir) as never))
      .resolves.toBeUndefined();
    expect(event.input.command).not.toBe("docker ps");

    const helperInput = extractHelperInput(event.input.command);
    expect(helperInput.runtimeConfig.dockerHost).toBe(`unix://${socketPath}`);
    expect(helperInput.runtimeConfig.network.allowUnixSockets).toContain(socketPath);
    expect(helperInput.runtimeConfig.filesystem.allowWrite).not.toContain(socketPath);
  });

  it("routes user Bash Docker ps through SRT despite wildcard host bypass", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const socketPath = path.join(projectDir, "docker.sock");
    mockDockerSocketPaths.mockReturnValue([socketPath]);
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const result = await pi.handlers.get("user_bash")?.(
      { command: "docker ps --format 'table {{.Names}}\\t{{.Status}}'", cwd: projectDir },
      createContext(projectDir) as never,
    );

    expect(result).toBeDefined();
    expect(result).toHaveProperty("operations");
  });

  it.each(["docker --help", "docker --version", "docker -h", "docker -v"])(
    "keeps client-only Docker command %s on the configured host bypass",
    async (command) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      const home = await makeSyntheticHome();
      const dockerConfig = path.join(home, ".docker", "config.json");
      await mkdir(path.dirname(dockerConfig), { recursive: true });
      await writeFile(dockerConfig, "{}", "utf8");
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const event = { toolName: "bash", input: { command } };
      await expect(pi.handlers.get("tool_call")?.(event, createContext(projectDir) as never))
        .resolves.toBeUndefined();
      expect(event.input.command).toBe(command);
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "routes a container command with a trailing help flag through SRT on %s",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      await makeSyntheticHome();
      const socketPath = path.join(projectDir, "docker.sock");
      mockDockerSocketPaths.mockReturnValue([socketPath]);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const command = "docker exec app mytool --help";
      if (surface === "tool_call") {
        const event = { toolName: "bash", input: { command } };
        await expect(pi.handlers.get("tool_call")?.(event, createContext(projectDir) as never))
          .resolves.toBeUndefined();
        expect(event.input.command).not.toBe(command);
        expect(extractHelperInput(event.input.command).runtimeConfig.dockerHost).toBe(`unix://${socketPath}`);
      } else {
        const result = await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, createContext(projectDir) as never);
        expect(result).toHaveProperty("operations");
      }
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "routes Docker daemon command forms through SRT on %s despite wildcard host bypass",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      await makeSyntheticHome();
      const socketPath = path.join(projectDir, "docker.sock");
      mockDockerSocketPaths.mockReturnValue([socketPath]);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const commands = [
        "docker ps && echo done",
        "bash -c 'docker ps'",
        "bash <<< 'docker ps'",
        "TRACE=1 docker ps",
        "env TRACE=1 docker ps",
        'echo "$(docker ps)"',
        `docker ps > ${path.join(projectDir, "docker-out")}`,
        "docker ps 2>&1",
        `docker ps &> ${path.join(projectDir, "docker-both-out")}`,
        ">& 1 docker ps",
        ">| out docker ps",
        "{fd}>out docker ps",
        "0<&0 docker ps",
        ">/dev/null< /dev/null docker ps",
        "docker ps\necho done",
      ];
      for (const command of commands) {
        const context = createContext(projectDir, {
          hasUI: command.includes("$(docker ps)"),
          choices: ["Yes"],
        });
        if (surface === "tool_call") {
          const event = { toolName: "bash", input: { command } };
          const result = await pi.handlers.get("tool_call")?.(event, context as never);
          if ([">& 1 docker ps", ">| out docker ps", "0<&0 docker ps", ">/dev/null< /dev/null docker ps"].includes(command)) {
            expect(result).toMatchObject({ block: true });
            expect(event.input.command).toBe(command);
            continue;
          }
          expect(result).toBeUndefined();
          expect(event.input.command).not.toBe(command);
          const runtimeConfig = extractHelperInput(event.input.command).runtimeConfig;
          expect(runtimeConfig.dockerHost).toBe(`unix://${socketPath}`);
          expect(runtimeConfig.network?.allowAllUnixSockets).toBe(process.platform === "linux" ? true : undefined);
          expect(runtimeConfig.network?.allowUnixSockets).toEqual([socketPath]);
        } else {
          const result = await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);
          expect(result, command).toHaveProperty("operations");
        }
      }
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "blocks command-level Docker host overrides on %s",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      await makeSyntheticHome();
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const commands = [
        "DOCKER_HOST=tcp://example.invalid docker ps",
        "DOCKER_CONFIG=/tmp/docker-config docker ps",
        "env DOCKER_HOST=tcp://example.invalid docker ps",
        "docker --host tcp://example.invalid ps",
        "docker --context production ps",
        "docker --config /tmp/docker-config ps",
        `docker --config "$CONFIG_DIR" ps`,
        "bash -c 'DOCKER_HOST=tcp://example.invalid docker ps'",
        "bash -c 'docker --host tcp://example.invalid ps'",
        "bash <<< 'docker --host tcp://example.invalid ps'",
        `bash <<< 'docker "$OPTIONS" ps'`,
        `bash <<< 'export DOCKER_HOST=tcp://example.invalid; docker ps'`,
        `bash <<< 'unset DOCKER_HOST; docker ps'`,
        `bash <<< 'source ./docker-env; docker ps'`,
        `bash <<< 'V=DOCKER_HOST; export "$V=tcp://example.invalid"; docker ps'`,
        "DOCKER_HOST=tcp://example.invalid; docker ps",
        "export DOCKER_HOST=tcp://example.invalid; docker ps",
        "export DOCKER_CONFIG=/tmp/docker-config; docker ps",
        "unset DOCKER_HOST; docker ps",
        "env -u DOCKER_HOST docker ps",
        "env -u DOCKER_CONFIG docker ps",
        "env --unset=DOCKER_CONTEXT docker ps",
        "env -i docker ps",
        "env --ignore-environment -S 'docker ps'",
        "env -i -S 'docker ps'",
        "X=1 DOCKER_HOST=tcp://example.invalid; docker ps",
        "bash -c 'export DOCKER_CONTEXT=production; docker ps'",
      ];
      for (const command of commands) {
        const result = surface === "tool_call"
          ? await pi.handlers.get("tool_call")?.({ toolName: "bash", input: { command } }, createContext(projectDir) as never)
          : await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, createContext(projectDir) as never);
        expect(JSON.stringify(result)).toContain("explicit Docker endpoint overrides are not supported");
      }
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "does not let GPG host fallback bypass a Docker SRT requirement on %s",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      await makeSyntheticHome();
      const socketPath = path.join(projectDir, "docker.sock");
      mockDockerSocketPaths.mockReturnValue([socketPath]);
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: {
          enabled: true,
          backend: "srt",
          defaultProfile: "online-dev",
          bypassCommands: ["*"],
          authExceptions: [{ match: "gpg *", kind: "gpg-auth", strategy: "ask-bypass" }],
        },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
      const command = "docker ps && gpg --sign artifact";
      const result = surface === "tool_call"
        ? await pi.handlers.get("tool_call")?.({ toolName: "bash", input: { command } }, context as never)
        : await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);

      expect(JSON.stringify(result)).toContain("cannot be combined with unsandboxed authentication");
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "routes file-backed AWS auth through SRT on %s despite wildcard host bypass",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      const credentialsPath = await makeSyntheticAwsCredentials();
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev", bypassCommands: ["*"] },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
      const command = "aws sts get-caller-identity";
      if (surface === "tool_call") {
        const event = { toolName: "bash", input: { command } };
        await expect(pi.handlers.get("tool_call")?.(event, context as never)).resolves.toBeUndefined();
        const helperInput = extractHelperInput(event.input.command);
        const canonicalCredentialsPath = await realpath(credentialsPath);
        expect(helperInput.runtimeConfig.filesystem.allowRead).toContain(canonicalCredentialsPath);
        expect(helperInput.runtimeConfig.filesystem.denyWrite).toContain(canonicalCredentialsPath);
      } else {
        const result = await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);
        expect(result).toHaveProperty("operations");
      }
      expect(context.ui.select).toHaveBeenCalledOnce();
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "keeps a later SSH deny visible after leading redirection on %s",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      const home = await makeSyntheticHome();
      const sshDir = path.join(home, ".ssh");
      await mkdir(sshDir, { recursive: true });
      await writeFile(path.join(sshDir, "id_ed25519"), "synthetic-private-key", "utf8");
      process.env.SSH_AUTH_SOCK = "";
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: {
          enabled: true,
          backend: "srt",
          defaultProfile: "online-dev",
          bypassCommands: ["*"],
          authExceptions: [
            { match: "ssh *", kind: "ssh-auth", strategy: "ask-bypass" },
            { match: "ssh trusted-host*", kind: "ssh-auth", strategy: "ask-bypass" },
            { match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" },
          ],
        },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir);
      const command = "ssh trusted-host && {fd}>out ssh blocked-host";
      if (surface === "tool_call") {
        const result = await pi.handlers.get("tool_call")?.(
          { toolName: "bash", input: { command } },
          context as never,
        );
        expect(result).toMatchObject({ block: true });
      } else {
        const result = await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);
        expect(result).not.toBeUndefined();
      }
      expect(context.ui.select).not.toHaveBeenCalled();
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "denies mixed or unsegmentable auth commands despite bypass approval on %s",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      const home = await makeSyntheticHome();
      const sshDir = path.join(home, ".ssh");
      const envPath = path.join(projectDir, ".env.local");
      await mkdir(sshDir, { recursive: true });
      await writeFile(path.join(sshDir, "id_ed25519"), "synthetic-private-key", "utf8");
      await writeFile(envPath, "TOKEN=synthetic-secret\n", "utf8");
      process.env.SSH_AUTH_SOCK = "";
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: {
          enabled: true,
          backend: "srt",
          defaultProfile: "online-dev",
          bypassCommands: ["*"],
          authExceptions: [
            { match: "ssh *", kind: "ssh-auth", strategy: "ask-bypass" },
            { match: "ssh trusted-host*", kind: "ssh-auth", strategy: "ask-bypass" },
            { match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" },
          ],
        },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const cases = [
        {
          command: 'ssh trusted-host && ssh blocked-host "$(printf x)"',
          reason: "could not be safely split",
        },
        {
          command: `ssh trusted-host && {fd}>out ssh blocked-host; gpg --version; cat ${envPath}`,
          reason: "Mixed authentication mechanisms",
        },
        {
          command: 'echo "$(ssh blocked-host)"',
          reason: "could not be safely split",
        },
        {
          command: "ssh 'blocked-host'",
          reason: "Matched auth exception rule",
        },
        {
          command: "ssh 'block'ed-host",
          reason: "Matched auth exception rule",
        },
        {
          command: "bash <<< 'ssh blocked-host'",
          reason: "Matched auth exception rule",
        },
        {
          command: 'bash <<< "ssh $TARGET"',
          reason: "SSH target could not be normalized",
        },
        {
          command: 'ssh "$HOST"',
          reason: "SSH target could not be normalized",
        },
      ];

      for (const { command, reason } of cases) {
        const context = createContext(projectDir, { hasUI: true, choices: ["Yes", "Allow once"] });
        const result = surface === "tool_call"
          ? await pi.handlers.get("tool_call")?.({ toolName: "bash", input: { command } }, context as never)
          : await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);
        expect(JSON.stringify(result)).toContain(reason);
      }
    },
  );

  it.each(["tool_call", "user_bash"] as const)(
    "preserves explicit file-auth host-bypass approval on %s",
    async (surface) => {
      const agentDir = await makeTempDir("pi-permission-agent-");
      const projectDir = await makeTempDir("pi-permission-project-");
      await makeSyntheticAwsCredentials();
      process.env.PI_CODING_AGENT_DIR = agentDir;
      await writeExtensionConfig(agentDir, {
        permission: { "*": "allow", bash: { "*": "allow" }, external_directory: { "*": "allow" } },
        sandbox: {
          enabled: true,
          backend: "srt",
          defaultProfile: "online-dev",
          bypassCommands: [],
          authExceptions: [{ match: "aws *", kind: "aws-auth", strategy: "ask-bypass" }],
        },
      });

      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
      const command = "aws sts get-caller-identity";
      if (surface === "tool_call") {
        const event = { toolName: "bash", input: { command } };
        await expect(pi.handlers.get("tool_call")?.(event, context as never)).resolves.toBeUndefined();
        expect(event.input.command).toBe(command);
      } else {
        const result = await pi.handlers.get("user_bash")?.({ command, cwd: projectDir }, context as never);
        expect(result).toBeUndefined();
      }
      expect(context.ui.select).toHaveBeenCalledOnce();
    },
  );

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

  it("auto-allows read-only host Bash chains without prompting", async () => {
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
    await mkdir(path.join(projectDir, "src"), { recursive: true });
    const context = createContext(projectDir, { hasUI: true, choices: ["Yes"] });
    const call = pi.handlers.get("tool_call")!;

    await expect(call(
      { toolName: "bash", toolCallId: "host-read", input: { command: "cd src && ls && git status" } },
      context as never,
    )).resolves.toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
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
      expect(classificationTexts.map((text) => text.split(" ", 1)[0])).toEqual([
        "tool=write", "tool=edit",
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

  it("ignores stale credential-scan config and denies .env reads", async () => {
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
    )).resolves.toMatchObject({ block: true });
  });

  it("auto-allows workspace .env reads but keeps selectors gated by path rules", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env.local");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeFile(envPath, "TOKEN=secret", "utf8");
    await writeExtensionConfig(agentDir, {
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
    )).resolves.toEqual({});
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

  it("auto-allows workspace dotenv consumers with SRT write denies", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env.local");
    const mixedCaseEnvPath = path.join(projectDir, ".Env.local");
    const missingEnvPath = path.join(projectDir, ".env.new");
    await writeFile(envPath, "TOKEN=secret-value\n# short\n", "utf8");
    await writeFile(mixedCaseEnvPath, "TOKEN=mixed-case-secret\n", "utf8");
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
        bypassCommands: ["*"],
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: ["**/.env", "**/.env.*"],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir);
    const event = {
      toolName: "bash",
      toolCallId: "t-dotenv-read",
      input: { command: `cat ${envPath}` },
    };
    const result = await pi.handlers.get("tool_call")?.(event, context as never);

    expect(result).toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
    const approvedPath = await realpath(envPath);
    const helperInput = extractHelperInput(event.input.command);
    expect(helperInput.runtimeConfig.filesystem.allowRead).toContain(approvedPath);
    expect(helperInput.runtimeConfig.filesystem.allowWrite).not.toContain(approvedPath);

    const directResult = await pi.handlers.get("tool_result")?.({
      toolCallId: "t-dotenv-read",
      toolName: "bash",
      input: event.input,
      content: [{ type: "text", text: "TOKEN=secret-value\n# short\n" }],
      details: {},
      isError: false,
    }, context as never);
    expect(directResult).toMatchObject({
      content: [{ type: "text", text: "TOKEN=****\n# ****\n" }],
    });

    const transformedCommand = `cat ${envPath} | sed 's/=/: /'`;
    const transformedEvent = {
      toolName: "bash",
      toolCallId: "t-dotenv-transform",
      input: { command: transformedCommand },
    };
    const transformedGate = await pi.handlers.get("tool_call")?.(transformedEvent, context as never);
    expect(transformedGate).toBeUndefined();
    const transformedOutput = await pi.handlers.get("tool_result")?.({
      toolCallId: "t-dotenv-transform",
      toolName: "bash",
      input: transformedEvent.input,
      content: [{ type: "text", text: "TOKEN: secret-value\n# short\n" }],
      details: { truncation: { content: "TOKEN: secret-value\n# short\n" } },
      isError: false,
    }, context as never);
    expect(transformedOutput).toMatchObject({
      content: [{ type: "text", text: "TOKEN: ****\n# ****\n" }],
      details: { truncation: { content: "TOKEN: ****\n# ****\n" } },
    });

    mockDockerSocketPaths.mockReturnValue([path.join(projectDir, "docker.sock")]);
    for (const [index, command] of [
      `docker run --env-file ${envPath} alpine:latest`,
      `docker run --env-file=${envPath} alpine:latest`,
    ].entries()) {
      const dockerEvent = {
        toolName: "bash",
        toolCallId: `t-dotenv-docker-${index}`,
        input: { command },
      };
      expect(await pi.handlers.get("tool_call")?.(dockerEvent, context as never)).toBeUndefined();
      const dockerHelperInput = extractHelperInput(dockerEvent.input.command);
      expect(dockerHelperInput.runtimeConfig.filesystem.allowRead).toContain(approvedPath);
      expect(dockerHelperInput.runtimeConfig.filesystem.allowWrite).not.toContain(approvedPath);
      expect(dockerHelperInput.runtimeConfig.filesystem.denyWrite).toContain(approvedPath);
      const dockerOutput = await pi.handlers.get("tool_result")?.({
        toolCallId: dockerEvent.toolCallId,
        toolName: "bash",
        input: dockerEvent.input,
        content: [{ type: "text", text: "TOKEN=secret-value" }],
        details: {},
        isError: false,
      }, context as never);
      expect(dockerOutput).toMatchObject({
        content: [{ type: "text", text: "TOKEN=****" }],
      });
    }

    for (const [protectedTarget, command] of [
      [mixedCaseEnvPath, `echo changed > ${mixedCaseEnvPath}`],
      [mixedCaseEnvPath, `python3 -c "open('${mixedCaseEnvPath}', 'w').write('changed')"`],
      [missingEnvPath, `echo changed > ${missingEnvPath}`],
      [missingEnvPath, `python3 -c "open('${missingEnvPath}', 'w').write('changed')"`],
    ]) {
      const writeEvent = {
        toolName: "bash",
        toolCallId: `t-dotenv-write-edge-${protectedTarget}-${command.startsWith("python3") ? "python" : "redirect"}`,
        input: { command },
      };
      const writeResult = await pi.handlers.get("tool_call")?.(writeEvent, context as never);
      if (writeResult === undefined) {
        const writeHelperInput = extractHelperInput(writeEvent.input.command);
        const expectedTarget = await realpath(protectedTarget).catch(() => path.resolve(protectedTarget));
        expect(writeHelperInput.runtimeConfig.filesystem.denyWrite).toContain(expectedTarget);
      } else {
        expect(writeResult).toMatchObject({ block: true });
      }
    }

    for (const command of [
      `echo changed > ${envPath}`,
      `rm ${envPath}`,
      `mv ${envPath} ${path.join(projectDir, "moved.env")}`,
      `tee ${envPath}`,
      `sed -i '' ${envPath}`,
      `cp ${envPath} ${path.join(projectDir, "copy.env")}`,
      `truncate -s 0 ${envPath}`,
      `python3 -c "open('${envPath}', 'w').write('changed')"`,
    ]) {
      const writeEvent = {
        toolName: "bash",
        toolCallId: `t-dotenv-write-${command}`,
        input: { command },
      };
      const writeResult = await pi.handlers.get("tool_call")?.(writeEvent, context as never);
      if (writeResult === undefined) {
        const writeHelperInput = extractHelperInput(writeEvent.input.command);
        expect(writeHelperInput.runtimeConfig.filesystem.denyWrite).toContain(approvedPath);
      } else {
        expect(writeResult).toMatchObject({ block: true });
      }
    }
  }, 20_000);

  it.each([
    ["Docker equals-form option", (envPath: string) => `docker run --env-file=.env.local alpine:latest`],
    ["interpreter literal", (_envPath: string) => `python3 -c "open('.env.local').read()"`],
  ])("preserves explicit path denies for %s", async (caseName, makeCommand) => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env.local");
    await writeFile(envPath, "TOKEN=synthetic-secret\n", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        path: { ".env.local": "deny" },
      },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: ["**/.env", "**/.env.*"],
          },
        },
      },
    });
    mockDockerSocketPaths.mockReturnValue([path.join(projectDir, "docker.sock")]);

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Yes"] });
    const result = await pi.handlers.get("tool_call")?.({
      toolName: "bash",
      toolCallId: `t-explicit-path-deny-${String(caseName).replaceAll(" ", "-")}`,
      input: { command: makeCommand(envPath) },
    }, context as never);
    expect(result).toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("prompts on explicit path asks before auto-granting a dotenv read", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    await writeFile(path.join(projectDir, ".env.local"), "TOKEN=synthetic-secret\n", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        path: { ".env.local": "ask" },
      },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: ["**/.env", "**/.env.*"],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["No"] });
    const result = await pi.handlers.get("tool_call")?.({
      toolName: "bash",
      toolCallId: "t-explicit-path-ask",
      input: { command: "docker run --env-file=.env.local alpine:latest" },
    }, context as never);
    expect(result).toMatchObject({ block: true });
    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it("value-masks dotenv output after an explicit path ask is approved", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env.local");
    await writeFile(envPath, "TOKEN=synthetic-secret\n", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: {
        "*": "allow",
        bash: { "*": "allow" },
        path: { ".env.local": "ask" },
      },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: ["**/.env", "**/.env.*"],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Yes", "Allow once"] });
    const event = {
      toolName: "bash",
      toolCallId: "t-explicit-path-ask-approved",
      input: { command: `cat ${envPath}` },
    };
    expect(await pi.handlers.get("tool_call")?.(event, context as never)).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledOnce();

    const result = await pi.handlers.get("tool_result")?.({
      toolCallId: event.toolCallId,
      toolName: "bash",
      input: event.input,
      content: [{ type: "text", text: "TOKEN=synthetic-secret\n" }],
      details: { truncation: { content: "TOKEN=synthetic-secret\n" } },
      isError: false,
    }, context as never);

    expect(result).toMatchObject({
      content: [{ type: "text", text: "TOKEN=****\n" }],
      details: { truncation: { content: "TOKEN=****\n" } },
    });
    expect(JSON.stringify(result)).not.toContain("synthetic-secret");
  });

  it.each([false, true])("redacts custom-profile masked output (error=%s)", async (isError) => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const envPath = path.join(projectDir, ".env");
    const customPath = path.join(projectDir, "private.cfg");
    await writeFile(envPath, "TOKEN=synthetic-dotenv-secret\n", "utf8");
    await writeFile(customPath, "KEY=synthetic-custom-secret\n", "utf8");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: { "*": "allow", bash: { "*": "allow" } },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        profiles: {
          "offline-dev": {
            network: false,
            env: { allow: [], deny: [] },
            maskedPaths: ["**/.env", "**/.env.*", "**/private.cfg"],
          },
        },
      },
    });

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow once"] });
    const command = `cat ${envPath} ${customPath}`;
    const event = {
      toolName: "bash",
      toolCallId: isError ? "t-mixed-masked-read-error" : "t-mixed-masked-read",
      input: { command },
    };
    expect(await pi.handlers.get("tool_call")?.(event, context as never)).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledTimes(1);

    const rawOutput = "TOKEN=synthetic-dotenv-secret\nKEY=synthetic-custom-secret\n";
    const result = await pi.handlers.get("tool_result")?.({
      toolCallId: event.toolCallId,
      toolName: "bash",
      input: event.input,
      content: [{ type: "text", text: rawOutput }],
      details: { truncation: { content: rawOutput } },
      isError,
    }, context as never);

    expect(JSON.stringify(result)).not.toContain("synthetic-dotenv-secret");
    expect(JSON.stringify(result)).not.toContain("synthetic-custom-secret");
  });

  it("honors explicit external-directory denies for direct protected reads", async () => {
    const originalHome = process.env.HOME;
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const homeDir = await makeTempDir("pi-permission-home-");
    const credentialPath = path.join(homeDir, ".aws", "credentials");
    await mkdir(path.dirname(credentialPath), { recursive: true });
    await writeFile(credentialPath, "TOKEN=synthetic-secret\n", "utf8");
    process.env.HOME = homeDir;
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeExtensionConfig(agentDir, {
      permission: { read: "allow", external_directory: { "*": "deny" } },
      sandbox: { enabled: false, backend: "srt", defaultProfile: "online-dev" },
    });

    try {
      const pi = createFakePi(["read"]);
      piPermissionSystemExtension(pi as never);
      const result = await pi.handlers.get("tool_call")?.(
        { toolName: "read", toolCallId: "t-denied-protected-read", input: { path: credentialPath } },
        createContext(projectDir) as never,
      );
      expect(result).toMatchObject({ block: true });
    } finally {
      if (originalHome === undefined) delete process.env.HOME;
      else process.env.HOME = originalHome;
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
