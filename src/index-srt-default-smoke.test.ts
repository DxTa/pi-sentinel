import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
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

function createFakePi(): FakePi {
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
    getAllTools: () => ["bash"],
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
  await writeFile(
    path.join(agentDir, "permissions.json"),
    JSON.stringify({
      yoloMode: false,
      permission: {
        "*": "deny",
        bash: {
          "echo ok": "allow",
          "pwd": "allow",
          "*sandbox-run.mjs*": "deny",
        },
      },
      network: { enabled: false, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: { enabled: true, backend: "srt", defaultProfile: "online-dev" },
      ...overrides,
    }),
    "utf8",
  );
}

function extractHelperInput(command: string) {
  const match = command.match(/PI_SRT_HELPER_INPUT_B64=([^\s]+)\s/);
  if (!match) throw new Error(`Missing helper input in command: ${command}`);
  return JSON.parse(Buffer.from(match[1]!, "base64").toString("utf8"));
}

describe("piPermissionSystemExtension SRT default smoke", () => {
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

  it("keeps persistent path grant live when revoke cannot be saved", async () => {
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

    await expect(revokeCommand.handler(grantId!, context)).rejects.toThrow();
    await statusCommand.handler("", context);
    const status = (context.ui.notify as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[0] as string;
    expect(status).toContain("Active grants: 1");
    expect(status).toContain(grantId!);
    expect(status).not.toContain("[persistent]");
  });

  it("rolls back sandbox capability revoke when a later layer cannot be saved", async () => {
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

    await expect(revokeCommand.handler("sandbox-network-global", context)).rejects.toThrow();
    expect(JSON.parse(await readFile(path.join(agentDir, "permissions.json"), "utf8")).sandbox.network).toBe(true);
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

  it("blocks user bash when persistent sandbox approval cannot be saved", async () => {
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
    const context = createContext(projectDir, { hasUI: true, choices: ["Allow globally"] });
    const result = await pi.handlers.get("user_bash")?.(
      { command: "curl https://example.com", cwd: projectDir },
      context as never,
    );

    expect(result).toMatchObject({ result: { exitCode: 1, output: expect.stringContaining("failed to persist") } });
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
