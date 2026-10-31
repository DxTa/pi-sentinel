import { existsSync } from "node:fs";
import { link, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import piPermissionSystemExtension from "./index.ts";

const ORIGINAL_HOME = process.env.HOME;
const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  // macOS tmpdir() is a symlink into /private; canonical paths keep cwd and targets comparable to the gate's.
  const dir = await realpath(await mkdtemp(path.join(tmpdir(), prefix)));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  delete process.env.PI_CODING_AGENT_DIR;
  if (ORIGINAL_HOME === undefined) delete process.env.HOME;
  else process.env.HOME = ORIGINAL_HOME;
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function createFakePi() {
  const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
  return {
    handlers,
    on: (name: string, handler: (event: unknown, ctx: unknown) => unknown) => {
      handlers.set(name, handler);
    },
    registerCommand: vi.fn(),
    getAllTools: () => ["bash", "read", "write", "edit"],
    setActiveTools: vi.fn(),
    events: { on: () => () => undefined, emit: () => undefined },
  };
}

function createContext(cwd: string, options: { hasUI: boolean; choices: string[] }) {
  const choices = [...options.choices];
  return {
    cwd,
    hasUI: options.hasUI,
    ui: {
      notify: vi.fn(),
      setStatus: vi.fn(),
      select: vi.fn(async () => choices.shift()),
    },
    sessionManager: { getEntries: () => [], getSessionDir: () => null },
  };
}

/** Hermetic HOME with a real ~/.config, so protected-path detection never depends on the machine. */
async function setup(mode: "manual" | "yolo" | "auto", hasUI: boolean, choices: string[]) {
  const home = await makeTempDir("pi-protected-home-");
  await mkdir(path.join(home, ".config"));
  process.env.HOME = home;
  const agentDir = await makeTempDir("pi-protected-agent-");
  const projectDir = await makeTempDir("pi-protected-project-");
  process.env.PI_CODING_AGENT_DIR = agentDir;
  await writeFile(
    path.join(agentDir, "permissions.json"),
    JSON.stringify({
      mode,
      yoloAskBashPatterns: [],
      permission: { "*": "allow", bash: { "*": "allow" } },
      network: { enabled: false, unknownDomains: "allow", allowedDomains: [], deniedDomains: [] },
      sandbox: {
        enabled: true,
        backend: "srt",
        defaultProfile: "offline-dev",
        bypassCommands: ["*"],
        profiles: { "offline-dev": { network: false, env: { allow: [], deny: [] }, maskedPaths: [] } },
      },
    }),
    "utf8",
  );
  const pi = createFakePi();
  piPermissionSystemExtension(pi as never);
  const context = createContext(projectDir, { hasUI, choices });
  // The sandbox wrapper rewrites input.command in place, so the caller keeps the input object.
  const run = (input: { command: string }) =>
    pi.handlers.get("tool_call")?.(
      { toolName: "bash", toolCallId: `t-${Math.random()}`, input },
      context as never,
    ) as Promise<{ block?: true; reason?: string } | undefined>;
  const configTarget = path.join(await realpath(path.join(home, ".config")), "pi-sentinel-approval-test");
  return { run, context, projectDir, home, configTarget };
}

/** Filesystem rules of the SRT helper that wraps an approved command. */
function srtFilesystem(command: string): { allowWrite: string[]; denyWrite: string[] } {
  const match = /PI_SRT_HELPER_INPUT_B64=(\S+)/.exec(command);
  if (!match) throw new Error("command was not wrapped in SRT");
  return JSON.parse(Buffer.from(match[1], "base64").toString("utf8")).runtimeConfig.filesystem;
}

describe("protected write approval", () => {
  it("makes only the approved ~/.config target writable and keeps the command in SRT", async () => {
    const { run, context, configTarget } = await setup("manual", true, ["Allow once"]);
    const input = { command: `echo x > ${configTarget}` };

    expect(await run(input)).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledOnce();
    expect(existsSync(configTarget)).toBe(true);
    const filesystem = srtFilesystem(input.command);
    expect(filesystem.allowWrite).toContain(configTarget);
    expect(filesystem.denyWrite).not.toContain(configTarget);
    expect(filesystem.denyWrite).toContain(`${configTarget}/*`);
  });

  it("keeps a masked project .env denied when the same command writes an approved target", async () => {
    const { run, projectDir, configTarget } = await setup("manual", true, ["Allow once"]);
    const envPath = path.join(projectDir, ".env");
    await writeFile(envPath, "TOKEN=x\n", "utf8");
    const input = { command: `echo x > ${configTarget}; echo y > ${envPath}` };

    expect(await run(input)).toBeUndefined();
    const envReal = await realpath(envPath);
    const filesystem = srtFilesystem(input.command);
    expect(filesystem.denyWrite).toContain(envReal);
    expect(filesystem.allowWrite).not.toContain(envReal);
  });

  it("prompts again for the next protected write", async () => {
    const { run, context, configTarget } = await setup("manual", true, ["Allow once", "Allow once"]);

    expect(await run({ command: `echo x > ${configTarget}` })).toBeUndefined();
    expect(await run({ command: `echo y > ${configTarget}` })).toBeUndefined();
    expect(context.ui.select).toHaveBeenCalledTimes(2);
  });

  it("blocks the ~/.config write when the approval is denied", async () => {
    const { run, context, configTarget } = await setup("manual", true, ["Deny"]);

    expect(await run({ command: `echo x > ${configTarget}` })).toMatchObject({ block: true });
    expect(context.ui.select).toHaveBeenCalledOnce();
    expect(existsSync(configTarget)).toBe(false);
  });

  it("blocks the ~/.config write without a UI instead of running it in SRT", async () => {
    const { run, context, configTarget } = await setup("manual", false, []);

    expect(await run({ command: `echo x > ${configTarget}` })).toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it.each(["yolo", "auto"] as const)("still prompts in %s mode and blocks on deny", async (mode) => {
    const { run, context, configTarget } = await setup(mode, true, ["Deny"]);

    expect(await run({ command: `echo x > ${configTarget}` })).toMatchObject({ block: true });
    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it("refuses an approved target that is hard-linked elsewhere", async () => {
    const { run, context, configTarget, projectDir } = await setup("manual", true, ["Allow once"]);
    await writeFile(configTarget, "", "utf8");
    await link(configTarget, path.join(projectDir, "elsewhere"));

    expect(await run({ command: `echo x > ${configTarget}` })).toMatchObject({ block: true });
    expect(context.ui.select).toHaveBeenCalledOnce();
  });

  it("refuses a target with trailing whitespace instead of granting its trimmed twin", async () => {
    const { run, context, configTarget } = await setup("manual", true, ["Allow once"]);

    expect(await run({ command: `echo x > "${configTarget} "` })).toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("refuses a glob target instead of granting the directory it expands to", async () => {
    const { run, context, home } = await setup("manual", true, ["Allow once"]);

    expect(await run({ command: `echo x > ${path.join(home, ".config", "**")}` })).toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("refuses a directory target instead of granting it", async () => {
    const { run, context, home } = await setup("manual", true, ["Allow once"]);

    expect(await run({ command: `echo x > ${path.join(home, ".config")}` })).toMatchObject({ block: true });
    expect(context.ui.select).not.toHaveBeenCalled();
  });

  it("keeps auto-allowing a protected read inside SRT without a prompt", async () => {
    const { run, context, home } = await setup("manual", true, ["Deny"]);
    const input = { command: `cat ${path.join(home, ".config", "gh", "hosts.yml")}` };

    expect(await run(input)).toBeUndefined();
    expect(context.ui.select).not.toHaveBeenCalled();
    expect(() => srtFilesystem(input.command)).not.toThrow();
  });
});
