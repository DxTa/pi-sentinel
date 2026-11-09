import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { editConfigList, listConfigList, type ConfigListContext } from "./config-lists";
import { SessionRules } from "./session-rules";

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeContext(): Promise<ConfigListContext & { sessionRules: SessionRules }> {
  const root = await mkdtemp(path.join(tmpdir(), "pi-config-rules-"));
  tempPaths.push(root);
  const agentDir = path.join(root, "agent");
  const cwd = path.join(root, "repo");
  await mkdir(agentDir, { recursive: true });
  await mkdir(cwd, { recursive: true });
  return { agentDir, cwd, sessionRules: new SessionRules() };
}

describe("permission rules in the config list router", () => {
  it("writes a project rule to the project file and lists it with its surface", async () => {
    const ctx = await makeContext();

    editConfigList(ctx, "permissionRule", "project", "git push *", "deny", "bash");

    expect(listConfigList(ctx, "permissionRule", "project")).toEqual([
      { surface: "bash", value: "git push *", state: "deny" },
    ]);
    const saved = JSON.parse(await readFile(path.join(ctx.cwd, ".pi", "sentinel.json"), "utf8"));
    expect(saved.permission.bash["git push *"]).toBe("deny");
  });

  it("removes a global rule", async () => {
    const ctx = await makeContext();
    await writeFile(
      path.join(ctx.agentDir, "sentinel.json"),
      JSON.stringify({ permission: { read: "allow" } }),
      "utf8",
    );

    editConfigList(ctx, "permissionRule", "global", "*", "remove", "read");

    expect(listConfigList(ctx, "permissionRule", "global")).toEqual([]);
  });

  it("keeps session rules in the session store and writes no file", async () => {
    const ctx = await makeContext();

    editConfigList(ctx, "permissionRule", "session", "git push *", "deny", "bash");

    expect(listConfigList(ctx, "permissionRule", "session")).toEqual([
      { surface: "bash", value: "git push *", state: "deny" },
    ]);
    expect(await readFile(path.join(ctx.cwd, ".pi", "sentinel.json"), "utf8").catch(() => null)).toBeNull();
  });

  it("requires a surface for rule edits", async () => {
    const ctx = await makeContext();

    expect(() => editConfigList(ctx, "permissionRule", "project", "git push *", "deny")).toThrow(/surface/);
  });
});
