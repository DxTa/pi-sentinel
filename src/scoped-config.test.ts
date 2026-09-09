import { mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  getScopedConfigPath,
  loadMergedScopedConfig,
  persistNetworkGrantToConfig,
  persistPermissionRuleToConfig,
  persistSandboxNetworkGrantToConfig,
  persistSandboxPathGrantToConfig,
  resolveConfinedConfigPath,
  removeNetworkGrantFromConfig,
  removeSandboxNetworkGrantFromConfig,
  removeSandboxPathGrantFromConfig,
} from "./scoped-config";

const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("resolveConfinedConfigPath", () => {
  it("returns a canonical workspace config path", async () => {
    const workspace = await makeTempDir("pi-scoped-workspace-");
    const configPath = path.join(workspace, ".pi", "permissions.json");

    expect(resolveConfinedConfigPath(configPath, workspace)).toBe(
      path.join(await realpath(workspace), ".pi", "permissions.json"),
    );
  });

  it("resolves symlinked workspace config parents", async () => {
    const workspace = await makeTempDir("pi-scoped-workspace-");
    const outside = await makeTempDir("pi-scoped-outside-");
    await symlink(outside, path.join(workspace, ".pi"));

    expect(resolveConfinedConfigPath(
      path.join(workspace, ".pi", "permissions.json"),
      workspace,
    )).toBe(path.join(await realpath(outside), "permissions.json"));
  });
});

describe("config shape validation", () => {
  it("rejects a non-object config root", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "permissions.json");
    await writeFile(configPath, "[]", "utf8");

    expect(() => loadMergedScopedConfig(dir, undefined, configPath)).toThrow(/config|object/i);
  });

  it("rejects a non-object sandbox section", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "permissions.json");
    await writeFile(configPath, JSON.stringify({ sandbox: "invalid" }), "utf8");

    expect(() => loadMergedScopedConfig(dir, undefined, configPath)).toThrow(/sandbox|object/i);
  });
});

describe("workspace config symlinks", () => {
  it("reads workspace config through a symlinked parent", async () => {
    const agentDir = await makeTempDir("pi-agent-");
    const workspace = await makeTempDir("pi-workspace-");
    const outside = await makeTempDir("pi-outside-");
    await writeFile(path.join(outside, "permissions.json"), JSON.stringify({ network: { enabled: true } }), "utf8");
    await symlink(outside, path.join(workspace, ".pi"));

    expect(loadMergedScopedConfig(agentDir, workspace).merged.network).toMatchObject({ enabled: true });
  });

  it("persists workspace config through a symlinked parent", async () => {
    const workspace = await makeTempDir("pi-workspace-");
    const outside = await makeTempDir("pi-outside-");
    const outsideConfig = path.join(outside, "permissions.json");
    await writeFile(outsideConfig, "{}", "utf8");
    await symlink(outside, path.join(workspace, ".pi"));

    persistPermissionRuleToConfig(
      path.join(workspace, ".pi", "permissions.json"),
      "bash",
      "echo unsafe",
      "allow",
      workspace,
    );

    expect(JSON.parse(await readFile(outsideConfig, "utf8"))).toEqual({
      permission: { bash: { "echo unsafe": "allow" } },
    });
  });
});

describe("workspace persistence", () => {
  it("persists through a canonicalized temporary workspace path", async () => {
    const workspace = await makeTempDir("pi-scoped-workspace-");
    const configPath = path.join(workspace, ".pi", "permissions.json");

    persistSandboxNetworkGrantToConfig(configPath, workspace);

    expect(JSON.parse(await readFile(configPath, "utf8"))).toEqual({
      sandbox: { network: true },
    });
  });
});

describe("getScopedConfigPath", () => {
  it("builds workspace config path", () => {
    expect(getScopedConfigPath("/agent", "/repo", "workspace")).toBe(
      "/repo/.pi/permissions.json",
    );
  });

  it("keeps writing existing legacy workspace config", async () => {
    const cwd = await makeTempDir("pi-repo-");
    const legacyPath = path.join(cwd, ".pi", "agent", "permissions.json");
    await mkdir(path.dirname(legacyPath), { recursive: true });
    await writeFile(legacyPath, "{}", "utf8");

    expect(getScopedConfigPath("/agent", cwd, "workspace")).toBe(legacyPath);
  });
});

describe("persistPermissionRuleToConfig", () => {
  it("writes nested permission rule with trailing newline", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "config.json");
    await writeFile(configPath, JSON.stringify({ debugLog: false }), "utf8");

    persistPermissionRuleToConfig(configPath, "bash", "git push *");

    const contents = await readFile(configPath, "utf8");
    expect(contents.endsWith("\n")).toBe(true);
    expect(JSON.parse(contents)).toEqual({
      debugLog: false,
      permission: {
        bash: {
          "git push *": "allow",
        },
      },
    });
  });
});

describe("persistSandboxNetworkGrantToConfig", () => {
  it("fails when config is malformed", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "permissions.json");
    await writeFile(configPath, "{ malformed", "utf8");

    expect(() => persistSandboxNetworkGrantToConfig(configPath)).toThrow(/Failed to read/);
    expect(() => removeSandboxNetworkGrantFromConfig(configPath)).toThrow(/Failed to read/);
  });

  it.each(["permissions.json", "sentinel.json"])("persists through a symlinked %s target", async (fileName) => {
    const dir = await makeTempDir("pi-scoped-config-");
    const realPath = path.join(dir, "real.json");
    const linkPath = path.join(dir, fileName);
    await writeFile(realPath, JSON.stringify({ sandbox: { enabled: true } }), "utf8");
    await symlink(realPath, linkPath);

    persistSandboxNetworkGrantToConfig(linkPath);

    expect(await realpath(linkPath)).toBe(realPath);
    expect(JSON.parse(await readFile(realPath, "utf8"))).toEqual({
      sandbox: { enabled: true, network: true },
    });
  });
});

describe("persistSandboxPathGrantToConfig", () => {
  it("appends read-only bind inside sandbox config", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "config.json");

    persistSandboxPathGrantToConfig(configPath, "/tmp/demo", "ro");

    await expect(readFile(configPath, "utf8")).resolves.toContain('"roBinds": [');
    expect(JSON.parse(await readFile(configPath, "utf8"))).toEqual({
      sandbox: {
        roBinds: ["/tmp/demo"],
      },
    });
  });
});

describe("persistent grant removal", () => {
  it("removes exact network and sandbox grant values", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "config.json");
    persistNetworkGrantToConfig(configPath, "api.example.com");
    persistNetworkGrantToConfig(configPath, "other.example.com");
    persistSandboxPathGrantToConfig(configPath, "/tmp/one", "ro");
    persistSandboxPathGrantToConfig(configPath, "/tmp/two", "rw");

    removeNetworkGrantFromConfig(configPath, "api.example.com");
    removeSandboxPathGrantFromConfig(configPath, "/tmp/one");

    expect(JSON.parse(await readFile(configPath, "utf8"))).toEqual({
      network: {
        enabled: true,
        allowedDomains: ["other.example.com"],
        deniedDomains: [],
      },
      sandbox: { rwBinds: ["/tmp/two"] },
    });
  });
});

describe("loadMergedScopedConfig", () => {
  it("merges workspace permission and network over global", async () => {
    const agentDir = await makeTempDir("pi-agent-");
    const cwd = await makeTempDir("pi-repo-");
    const bundledPath = path.join(agentDir, "bundled-config.json");
    const globalPath = getScopedConfigPath(agentDir, cwd, "global");
    const workspacePath = getScopedConfigPath(agentDir, cwd, "workspace");
    const legacyWorkspacePath = path.join(cwd, ".pi", "agent", "permissions.json");

    await writeFile(
      bundledPath,
      JSON.stringify({
        network: { unknownDomains: "ask", allowedDomains: ["bundled.example.com"] },
        sandbox: { enabled: false, roBinds: ["/bundled"] },
        permission: { bash: { "git diff": "ask" } },
      }),
      "utf8",
    );
    await mkdir(path.dirname(globalPath), { recursive: true });
    await mkdir(path.dirname(workspacePath), { recursive: true });
    await mkdir(path.dirname(legacyWorkspacePath), { recursive: true });
    await writeFile(
      globalPath,
      JSON.stringify({
        network: {
          allowedDomains: ["global.example.com"],
          deniedDomains: ["api.example.com"],
        },
        sandbox: { enabled: true, roBinds: ["/global"] },
        permission: {
          bash: {
            "git status": "allow",
          },
        },
      }),
      "utf8",
    );
    await writeFile(
      legacyWorkspacePath,
      JSON.stringify({
        network: {
          allowedDomains: ["legacy.example.com"],
        },
      }),
      "utf8",
    );
    await writeFile(
      workspacePath,
      JSON.stringify({
        network: {
          allowedDomains: ["api.example.com"],
        },
        sandbox: { roBinds: ["/project"] },
        permission: {
          bash: {
            "git push *": "allow",
          },
        },
      }),
      "utf8",
    );

    const merged = loadMergedScopedConfig(agentDir, cwd, bundledPath);
    expect(merged.merged.network).toEqual({
      unknownDomains: "ask",
      allowedDomains: [
        "bundled.example.com",
        "global.example.com",
        "legacy.example.com",
        "api.example.com",
      ],
      deniedDomains: ["api.example.com"],
    });
    expect(merged.merged.sandbox).toEqual({
      enabled: true,
      roBinds: ["/bundled", "/global", "/project"],
    });
    expect(merged.merged.permission).toEqual({
      bash: {
        "git diff": "ask",
        "git status": "allow",
        "git push *": "allow",
      },
    });
  });
});

describe("persistNetworkGrantToConfig", () => {
  it("does not overwrite malformed config", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "config.json");
    const malformed = "{ malformed\n";
    await writeFile(configPath, malformed, "utf8");

    expect(() => persistNetworkGrantToConfig(configPath, "api.github.com")).toThrow("Failed to read network config");

    await expect(readFile(configPath, "utf8")).resolves.toBe(malformed);
  });

  it("creates new config directories with owner-only permissions", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "nested", "permissions.json");

    persistNetworkGrantToConfig(configPath, "api.github.com");

    expect((await stat(path.dirname(configPath))).mode & 0o777).toBe(0o700);
  });

  it("follows symlinked config targets", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const realPath = path.join(dir, "real.json");
    const linkPath = path.join(dir, "permissions.json");
    await writeFile(realPath, JSON.stringify({ debugLog: false }), "utf8");
    await symlink(realPath, linkPath);

    persistNetworkGrantToConfig(linkPath, "api.github.com");

    expect(await realpath(linkPath)).toBe(realPath);
    expect(JSON.parse(await readFile(realPath, "utf8"))).toMatchObject({
      debugLog: false,
      network: { allowedDomains: ["api.github.com"] },
    });
  });

  it("keeps trailing newline when adding domain", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "config.json");
    await writeFile(configPath, JSON.stringify({ debugLog: false }), "utf8");

    persistNetworkGrantToConfig(configPath, "api.github.com");

    const contents = await readFile(configPath, "utf8");
    expect(contents.endsWith("\n")).toBe(true);
  });

  it("moves a denied domain out of allowed domains", async () => {
    const dir = await makeTempDir("pi-scoped-config-");
    const configPath = path.join(dir, "config.json");
    await writeFile(
      configPath,
      JSON.stringify({ network: { allowedDomains: ["api.github.com"] } }),
      "utf8",
    );

    persistNetworkGrantToConfig(configPath, "api.github.com", "deny");

    expect(JSON.parse(await readFile(configPath, "utf8"))).toEqual({
      network: {
        enabled: true,
        allowedDomains: [],
        deniedDomains: ["api.github.com"],
      },
    });
  });
});
