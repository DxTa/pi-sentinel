import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { editConfigList, listConfigList, type ConfigListContext } from "./config-lists";
import { clearSessionLists } from "./session-lists";

const tempPaths: string[] = [];

afterEach(async () => {
  clearSessionLists();
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeContext(extra: Partial<ConfigListContext> = {}): Promise<ConfigListContext> {
  const root = await mkdtemp(path.join(tmpdir(), "pi-config-session-"));
  tempPaths.push(root);
  return { agentDir: path.join(root, "agent"), cwd: path.join(root, "repo"), ...extra };
}

describe("session scope for host fallback and yolo ask patterns", () => {
  it("keeps host fallback commands in memory until removed", async () => {
    const ctx = await makeContext();

    editConfigList(ctx, "hostFallback", "session", "docker compose", "on");
    expect(listConfigList(ctx, "hostFallback", "session")).toEqual([{ value: "docker compose", state: "on" }]);

    editConfigList(ctx, "hostFallback", "session", "docker compose", "remove");
    expect(listConfigList(ctx, "hostFallback", "session")).toEqual([]);
  });

  it("keeps yolo ask patterns in memory until removed", async () => {
    const ctx = await makeContext();

    editConfigList(ctx, "yoloAskPattern", "session", "rm -rf *", "on");
    expect(listConfigList(ctx, "yoloAskPattern", "session")).toEqual([{ value: "rm -rf *", state: "on" }]);

    editConfigList(ctx, "yoloAskPattern", "session", "rm -rf *", "remove");
    expect(listConfigList(ctx, "yoloAskPattern", "session")).toEqual([]);
  });
});

describe("session scope for sandbox path grants", () => {
  it("delegates path grants to the sandbox grant store", async () => {
    const granted: Array<[string, string]> = [];
    const revoked: string[] = [];
    let live: Array<{ value: string; mode: "ro" | "rw" }> = [];
    const sandboxGrants = {
      listPathGrants: () => live,
      grantPath: (value: string, mode: "ro" | "rw") => {
        granted.push([value, mode]);
        live = [...live, { value, mode }];
      },
      revokePath: (value: string) => {
        revoked.push(value);
        live = live.filter((grant) => grant.value !== value);
      },
    };
    const ctx = await makeContext({ sandboxGrants });

    editConfigList(ctx, "sandboxPath", "session", "/data/out", "rw");
    expect(listConfigList(ctx, "sandboxPath", "session")).toEqual([{ value: "/data/out", state: "rw" }]);
    expect(granted).toEqual([["/data/out", "rw"]]);

    editConfigList(ctx, "sandboxPath", "session", "/data/out", "remove");
    expect(revoked).toEqual(["/data/out"]);
    expect(listConfigList(ctx, "sandboxPath", "session")).toEqual([]);
  });

  it("refuses session path edits without a sandbox grant store", async () => {
    const ctx = await makeContext();

    expect(() => editConfigList(ctx, "sandboxPath", "session", "/data/out", "rw")).toThrow(/session scope/);
  });
});
