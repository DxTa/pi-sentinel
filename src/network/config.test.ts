import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { loadDomainPolicy } from "./config.js";

const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  delete process.env.PI_CODING_AGENT_DIR;
  vi.restoreAllMocks();
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("loadDomainPolicy", () => {
  it("asks before unconfigured domain access", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    process.env.PI_CODING_AGENT_DIR = agentDir;

    expect(loadDomainPolicy(undefined).unknownDomains).toBe("ask");
  });

  it("ignores retired domain-gate.json files", async () => {
    const agentDir = await makeTempDir("pi-permission-agent-");
    const projectDir = await makeTempDir("pi-permission-project-");
    const projectConfigDir = path.join(projectDir, ".pi");

    process.env.PI_CODING_AGENT_DIR = agentDir;
    await mkdir(projectConfigDir, { recursive: true });
    await writeFile(
      path.join(projectConfigDir, "domain-gate.json"),
      JSON.stringify({ enabled: false, allowedDomains: ["example.com"] }),
      "utf8",
    );

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const policy = loadDomainPolicy(undefined);

    expect(policy.enabled).toBe(true);
    expect(policy.allowedDomains).toEqual([]);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
