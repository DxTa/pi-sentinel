import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import piPermissionSystemExtension from "./index";

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

function createFakePi() {
  const commands = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> | void }>();
  const handlers = new Map<string, (event: unknown, ctx: unknown) => Promise<unknown> | unknown>();
  const eventHandlers = new Map<string, Array<(event: unknown) => unknown>>();
  return {
    registerCommand: (name: string, command: { handler: (args: string, ctx: unknown) => Promise<void> | void }) => {
      commands.set(name, command);
    },
    on: (name: string, handler: (event: unknown, ctx: unknown) => Promise<unknown> | unknown) => {
      handlers.set(name, handler);
    },
    getAllTools: () => ["bash"],
    setActiveTools: vi.fn(),
    events: {
      on: (name: string, handler: (event: unknown) => unknown) => {
        const list = eventHandlers.get(name) ?? [];
        list.push(handler);
        eventHandlers.set(name, list);
        return () => {
          eventHandlers.set(name, (eventHandlers.get(name) ?? []).filter((entry) => entry !== handler));
        };
      },
      emit: (name: string, payload: unknown) => {
        for (const handler of eventHandlers.get(name) ?? []) handler(payload);
      },
    },
    commands,
    handlers,
  };
}

describe("piPermissionSystemExtension workspace config", () => {
  it("shows workspace allows without erasing global domain denies", async () => {
    const agentDir = await makeTempDir("pi-agent-");
    const projectDir = await makeTempDir("pi-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;

    const globalConfigPath = path.join(agentDir, "permissions.json");
    const workspaceConfigPath = path.join(projectDir, ".pi", "permissions.json");
    await mkdir(path.dirname(globalConfigPath), { recursive: true });
    await mkdir(path.dirname(workspaceConfigPath), { recursive: true });

    await writeFile(
      globalConfigPath,
      JSON.stringify({
        network: {
          enabled: true,
          unknownDomains: "deny",
          deniedDomains: ["api.example.com"],
        },
      }),
      "utf8",
    );
    await writeFile(
      workspaceConfigPath,
      JSON.stringify({
        network: {
          allowedDomains: ["api.example.com"],
        },
      }),
      "utf8",
    );

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);

    const notify = vi.fn();
    await pi.commands.get("domain-gate")?.handler("", {
      cwd: projectDir,
      ui: { notify },
    });

    expect(notify).toHaveBeenCalledTimes(1);
    const [message, level] = notify.mock.calls[0] ?? [];
    expect(level).toBe("info");
    expect(message).toContain("Allowed: api.example.com");
    expect(message).toContain("Denied: api.example.com");
  });

  it("keeps commands host-accessible while ignoring legacy project-grants", { timeout: 30_000 }, async () => {
    const agentDir = await makeTempDir("pi-agent-");
    const projectDir = await makeTempDir("pi-project-");
    // Keep old package path as a legacy fixture; renamed extension must ignore it.
    const legacyGrantPath = path.join(projectDir, ".pi", "pi-permission-system", "project-grants.json");
    process.env.PI_CODING_AGENT_DIR = agentDir;

    const globalConfigPath = path.join(agentDir, "permissions.json");
    await mkdir(path.dirname(globalConfigPath), { recursive: true });
    await mkdir(path.dirname(legacyGrantPath), { recursive: true });
    await writeFile(
      globalConfigPath,
      JSON.stringify({
        permission: {
          bash: {
            pwd: "allow",
          },
        },
        sandbox: {
          enabled: true,
          backend: "srt",
          defaultProfile: "online-dev",
          bypassCommands: ["*"],
        },
      }),
      "utf8",
    );
    await writeFile(
      legacyGrantPath,
      JSON.stringify({ roBinds: ["/tmp/legacy-bind"], rwBinds: [] }),
      "utf8",
    );

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);

    const event = { toolName: "bash", input: { command: "pwd" } };
    const result = await pi.handlers.get("tool_call")?.(event, {
      cwd: projectDir,
      hasUI: false,
      ui: { notify: vi.fn() },
      sessionManager: { getEntries: () => [], getSessionDir: () => null },
    });

    expect(result).toBeUndefined();
    expect(event.input.command).toBe("pwd");
  });
});
