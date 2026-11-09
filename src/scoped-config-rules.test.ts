import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { listPermissionRules, removePermissionRule } from "./scoped-config";

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("permission rules in one scope file", () => {
  it("lists string and pattern forms, then removes a pattern and a last-pattern surface", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "pi-scoped-rules-"));
    tempPaths.push(cwd);
    const configPath = path.join(cwd, ".pi", "sentinel.json");
    await mkdir(path.dirname(configPath), { recursive: true });
    await writeFile(
      configPath,
      JSON.stringify({
        permission: {
          read: "allow",
          bash: { "git status": "allow", "git push *": "deny" },
        },
      }),
      "utf8",
    );

    expect(listPermissionRules(configPath, cwd)).toEqual([
      { surface: "read", pattern: "*", action: "allow" },
      { surface: "bash", pattern: "git status", action: "allow" },
      { surface: "bash", pattern: "git push *", action: "deny" },
    ]);

    removePermissionRule(configPath, "bash", "git push *", cwd);
    removePermissionRule(configPath, "read", "*", cwd);

    expect(listPermissionRules(configPath, cwd)).toEqual([
      { surface: "bash", pattern: "git status", action: "allow" },
    ]);
  });
});
