import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import piPermissionSystemExtension from "./index";

vi.mock("@earendil-works/pi-coding-agent", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  getSettingsListTheme: () => ({}),
}));

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


  it("warns once when a project mode shadows a global mode save", { timeout: 30_000 }, async () => {
    const agentDir = await makeTempDir("pi-agent-mode-shadow-");
    const projectDir = await makeTempDir("pi-project-mode-shadow-");
    const previousMode = process.env.PI_SENTINEL_MODE;
    delete process.env.PI_SENTINEL_MODE;
    process.env.PI_CODING_AGENT_DIR = agentDir;

    const globalConfigPath = path.join(agentDir, "permissions.json");
    const workspaceConfigPath = path.join(projectDir, ".pi", "permissions.json");
    await mkdir(path.dirname(workspaceConfigPath), { recursive: true });
    await writeFile(globalConfigPath, JSON.stringify({ mode: "manual" }), "utf8");
    await writeFile(workspaceConfigPath, JSON.stringify({ mode: "manual" }), "utf8");

    try {
      const pi = createFakePi();
      piPermissionSystemExtension(pi as never);
      const notify = vi.fn();
      const ctx = {
        cwd: projectDir,
        hasUI: true,
        ui: { notify, setStatus: vi.fn() },
        sessionManager: { getEntries: () => [], getSessionDir: () => null },
      };

      notify.mockClear();
      // The settings picker only offers scopes that take effect; the command can still target global.
      await pi.commands.get("sentinel")?.handler("mode yolo global", ctx);

      expect(notify).toHaveBeenCalledTimes(1);
      expect(notify).toHaveBeenCalledWith(
        expect.stringContaining("Saved mode 'yolo' → global (" + globalConfigPath + ")"),
        "warning",
      );
      expect(notify.mock.calls[0]?.[0]).toContain(
        "Effective: manual (from project, which overrides the saved global value)",
      );
      expect(JSON.parse(await readFile(globalConfigPath, "utf8")).mode).toBe("yolo");
    } finally {
      if (previousMode === undefined) delete process.env.PI_SENTINEL_MODE;
      else process.env.PI_SENTINEL_MODE = previousMode;
    }
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

describe("piPermissionSystemExtension session mode", () => {
  it("drops a session-scope mode when a new session starts", { timeout: 30_000 }, async () => {
    const agentDir = await makeTempDir("pi-agent-");
    const projectDir = await makeTempDir("pi-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;
    await writeFile(path.join(agentDir, "permissions.json"), JSON.stringify({ mode: "manual" }), "utf8");

    const pi = createFakePi();
    piPermissionSystemExtension(pi as never);
    const notify = vi.fn();
    const ctx = {
      cwd: projectDir,
      hasUI: true,
      ui: { notify, setStatus: vi.fn() },
      sessionManager: { getEntries: () => [], getSessionDir: () => null },
    };
    const modePattern = new RegExp("mode=([a-z-]+)");
    const lastShownMode = async () => {
      notify.mockClear();
      await pi.commands.get("sentinel")?.handler("show", ctx);
      return modePattern.exec(String(notify.mock.calls[0]?.[0]))?.[1];
    };

    await pi.handlers.get("session_start")?.({ reason: "startup" }, ctx);
    expect(await lastShownMode()).toBe("manual");

    await pi.commands.get("sentinel")?.handler("mode yolo session", ctx);
    expect(await lastShownMode()).toBe("yolo");

    await pi.handlers.get("session_start")?.({ reason: "new" }, ctx);
    expect(await lastShownMode()).toBe("manual");
  });
});
