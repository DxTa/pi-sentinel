import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { listNetworkDomains, setNetworkDomainState } from "./scoped-config";

const tempPaths: string[] = [];

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeWorkspace(): Promise<{ cwd: string; configPath: string }> {
  const cwd = await mkdtemp(path.join(tmpdir(), "pi-scoped-list-"));
  tempPaths.push(cwd);
  const configPath = path.join(cwd, ".pi", "sentinel.json");
  await mkdir(path.dirname(configPath), { recursive: true });
  return { cwd, configPath };
}

describe("network domain entries in one scope file", () => {
  it("allow, flip to deny, then remove leaves the domain in neither list", async () => {
    const { cwd, configPath } = await makeWorkspace();

    setNetworkDomainState(configPath, "api.example.com", "allow", cwd);
    expect(listNetworkDomains(configPath, cwd)).toEqual({ allowed: ["api.example.com"], denied: [] });

    setNetworkDomainState(configPath, "api.example.com", "deny", cwd);
    expect(listNetworkDomains(configPath, cwd)).toEqual({ allowed: [], denied: ["api.example.com"] });

    setNetworkDomainState(configPath, "api.example.com", "remove", cwd);
    expect(listNetworkDomains(configPath, cwd)).toEqual({ allowed: [], denied: [] });
  });

  it("keeps unrelated sections of the file", async () => {
    const { cwd, configPath } = await makeWorkspace();
    await mkdir(path.dirname(configPath), { recursive: true });
    const { writeFile } = await import("node:fs/promises");
    await writeFile(configPath, JSON.stringify({ debugLog: true }), "utf8");

    setNetworkDomainState(configPath, "api.example.com", "allow", cwd);

    const saved = JSON.parse(await readFile(configPath, "utf8"));
    expect(saved.debugLog).toBe(true);
    expect(saved.network.allowedDomains).toEqual(["api.example.com"]);
  });

  it("refuses a config path outside the workspace", async () => {
    const { cwd } = await makeWorkspace();

    expect(() => setNetworkDomainState("/etc/sentinel.json", "api.example.com", "allow", cwd)).toThrow();
  });
});
