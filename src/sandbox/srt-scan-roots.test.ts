
import { mkdtemp, mkdir, writeFile, chmod, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

const scanned: string[] = [];
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: ((bin: string, args: string[], opts: unknown) => {
      if (bin === "/usr/bin/find") {
        scanned.push(args[0]!);
        return Buffer.alloc(0);
      }
      return (actual.execFileSync as (...values: unknown[]) => unknown)(bin, args, opts);
    }) as typeof actual.execFileSync,
  };
});
import { buildSrtCommandSpec } from "./srt-command-spec.js";

const temp: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(temp.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("masked scan roots", () => {
  it("scans the workspace but not PATH tool directories under the home directory", async () => {
    scanned.length = 0;
    const home = await mkdtemp(path.join(tmpdir(), "pi-scan-home-"));
    const repo = await mkdtemp(path.join(tmpdir(), "pi-scan-repo-"));
    temp.push(home, repo);
    const toolDir = path.join(home, "Android", "Sdk", "platform-tools");
    await mkdir(toolDir, { recursive: true });
    vi.stubEnv("HOME", home);
    vi.stubEnv("PATH", [toolDir, "/usr/bin"].join(":"));

    buildSrtCommandSpec({
      command: "ls",
      cwd: repo,
      repoRoot: repo,
      sandboxConfig: { enabled: true, backend: "srt", profiles: {}, defaultProfile: "online-dev", roBinds: [], rwBinds: [] } as never,
      profile: { name: "online-dev", network: true, allowDocker: false, roBinds: [], rwBinds: [], env: { allow: [], deny: [] }, maskedPaths: [] } as never,
    });

    expect(scanned.some((root) => root.endsWith(path.basename(repo)))).toBe(true);
    expect(scanned.some((root) => root.includes("platform-tools"))).toBe(false);
  });
});
