import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { clearSessionDomains } from "./network/session-domains";
import { editConfigList, listConfigList, type ConfigListContext } from "./config-lists";

const tempPaths: string[] = [];

afterEach(async () => {
  clearSessionDomains();
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeContext(): Promise<ConfigListContext> {
  const root = await mkdtemp(path.join(tmpdir(), "pi-config-lists-"));
  tempPaths.push(root);
  const agentDir = path.join(root, "agent");
  const cwd = path.join(root, "repo");
  await mkdir(agentDir, { recursive: true });
  await mkdir(cwd, { recursive: true });
  return { agentDir, cwd };
}

describe("config list router", () => {
  it("writes project and global network domains to their own files", async () => {
    const ctx = await makeContext();

    editConfigList(ctx, "networkDomain", "project", "api.example.com", "allow");
    editConfigList(ctx, "networkDomain", "global", "docs.example.com", "deny");

    expect(listConfigList(ctx, "networkDomain", "project")).toEqual([
      { value: "api.example.com", state: "allow" },
    ]);
    expect(listConfigList(ctx, "networkDomain", "global")).toEqual([
      { value: "docs.example.com", state: "deny" },
    ]);
    const projectFile = JSON.parse(await readFile(path.join(ctx.cwd, ".pi", "sentinel.json"), "utf8"));
    expect(projectFile.network.allowedDomains).toEqual(["api.example.com"]);
    const globalFile = JSON.parse(await readFile(path.join(ctx.agentDir, "sentinel.json"), "utf8"));
    expect(globalFile.network.deniedDomains).toEqual(["docs.example.com"]);
  });

  it("keeps session domain grants in memory and writes no file", async () => {
    const ctx = await makeContext();

    editConfigList(ctx, "networkDomain", "session", "blocked.example.com", "deny");

    expect(listConfigList(ctx, "networkDomain", "session")).toEqual([
      { value: "blocked.example.com", state: "deny" },
    ]);
    expect(await readFile(path.join(ctx.cwd, ".pi", "sentinel.json"), "utf8").catch(() => null)).toBeNull();
  });

  it("rejects session scope for sandbox paths without a grant store", async () => {
    const ctx = await makeContext();

    expect(() => editConfigList(ctx, "sandboxPath", "session", "/data/out", "rw")).toThrow(
      /session scope/,
    );
  });
});
