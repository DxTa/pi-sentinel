import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir, homedir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { EXTENSION_ROOT } from "../extension-config.js";
import { detectExternalPaths } from "./external-path-gate.js";
import {
  createSandboxVisibilityMatcher,
  expandHomePath,
  getSandboxTempPaths,
} from "./sandbox-visible-paths.js";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";

const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function makeProfile(overrides: Partial<ResolvedSandboxProfile> = {}): ResolvedSandboxProfile {
  return {
    name: "offline-dev",
    network: false,
    allowDocker: false,
    roBinds: [],
    rwBinds: [],
    env: { allow: [], deny: [] },
    maskedPaths: [],
    ...overrides,
  };
}

function makeConfig(overrides: Partial<SandboxConfig> = {}): SandboxConfig {
  return {
    enabled: true,
    profiles: {},
    defaultProfile: "offline-dev",
    roBinds: [],
    rwBinds: [],
    ...overrides,
  };
}

describe("expandHomePath", () => {
  it("expands tilde paths using current home directory", () => {
    expect(expandHomePath("~/demo")).toBe(path.resolve(homedir(), "demo"));
    expect(expandHomePath("~")).toBe(homedir());
    expect(expandHomePath("/tmp/demo")).toBe("/tmp/demo");
  });
});

describe("createSandboxVisibilityMatcher", () => {
  it("treats repo root, cwd, configured binds, and narrow runtime paths as visible", () => {
    const repoRoot = "/workspace/repo";
    const cwd = "/workspace/repo/packages/app";
    const profile = makeProfile({ roBinds: ["~/extra-ro"], rwBinds: ["/opt/shared"] });
    const config = makeConfig({ roBinds: ["/srv/global-ro"], rwBinds: ["~/global-rw"] });

    const isVisible = createSandboxVisibilityMatcher({ repoRoot, cwd, profile, config });

    expect(isVisible(repoRoot)).toBe(true);
    expect(isVisible(path.join(repoRoot, "src/index.ts"))).toBe(true);
    expect(isVisible(cwd)).toBe(true);
    expect(isVisible(path.join(cwd, "subdir/file.txt"))).toBe(true);
    expect(isVisible("/srv/global-ro/file.txt")).toBe(true);
    expect(isVisible(path.join(homedir(), "global-rw/file.txt"))).toBe(true);
    expect(isVisible(path.join(homedir(), "extra-ro/file.txt"))).toBe(true);
    expect(isVisible("/usr/bin/git")).toBe(true);
    expect(isVisible("/opt/homebrew/opt/python@3.14/bin/python3.14")).toBe(true);
    expect(isVisible("/var/select/sh")).toBe(true);
    expect(isVisible(path.join(homedir(), ".config/gh/hosts.yml"))).toBe(false);
    expect(isVisible(path.join(homedir(), ".aws/config"))).toBe(false);
    expect(isVisible(path.join(homedir(), ".ssh/config"))).toBe(false);
    expect(isVisible(path.join(homedir(), ".gitconfig"))).toBe(false);
  });

  it("resolves relative bind paths against repo root, not the extension process cwd", async () => {
    const repoRoot = await makeTempDir("pi-visible-repo-");
    const siblingDir = path.join(repoRoot, "..", "shared-visible");
    await mkdir(siblingDir, { recursive: true });

    const isVisible = createSandboxVisibilityMatcher({
      repoRoot,
      cwd: repoRoot,
      profile: makeProfile({ roBinds: ["../shared-visible"] }),
      config: makeConfig(),
    });

    expect(isVisible(path.join(siblingDir, "file.txt"))).toBe(true);
  });

  it("allows pi-sentinel package assets while keeping unrelated home paths out of scope", () => {
    const isVisible = createSandboxVisibilityMatcher({
      repoRoot: "/workspace/repo",
      cwd: "/workspace/repo",
      profile: makeProfile(),
      config: makeConfig(),
    });

    expect(isVisible(path.join(EXTENSION_ROOT, "bin/sandbox-run.mjs"))).toBe(true);
    expect(isVisible(path.join(homedir(), "private-not-bound/secret.txt"))).toBe(false);
    expect(isVisible(path.join(homedir(), ".cargo/credentials.toml"))).toBe(false);
    expect(isVisible(path.join(homedir(), ".bun/install/cache/pkg.tgz"))).toBe(false);
    expect(isVisible(path.join(homedir(), ".local/state/other-app/state.json"))).toBe(false);
    expect(isVisible(path.join(homedir(), ".local/share/uv/python/cpython-3.13.0/bin/python3"))).toBe(true);
    expect(isVisible(path.join(homedir(), ".cache/uv/archive-v0/interpreter.msgpack"))).toBe(true);
    expect(isVisible(path.join(homedir(), ".cargo/bin/cargo"))).toBe(true);
    expect(isVisible(path.join(homedir(), ".bun/bin/bun"))).toBe(true);
  });

  it("treats configured infrastructure paths as visible", () => {
    const infrastructureRoot = path.join(homedir(), ".pi", "agent");
    const isVisible = createSandboxVisibilityMatcher({
      repoRoot: "/workspace/repo",
      cwd: "/workspace/repo",
      profile: makeProfile(),
      config: makeConfig({ infrastructureReadPaths: [infrastructureRoot] }),
    });

    expect(isVisible(path.join(infrastructureRoot, "agents/agents-index.tsv"))).toBe(true);
  });

  it("exposes Docker CLI directory read-only only for direct Docker commands", () => {
    const dockerIsVisible = createSandboxVisibilityMatcher({
      repoRoot: "/workspace/repo",
      cwd: "/workspace/repo",
      command: "docker compose version",
      profile: makeProfile(),
      config: makeConfig(),
    });
    const otherCommandIsVisible = createSandboxVisibilityMatcher({
      repoRoot: "/workspace/repo",
      cwd: "/workspace/repo",
      command: "cat ~/.docker/config.json",
      profile: makeProfile(),
      config: makeConfig(),
    });

    expect(dockerIsVisible(path.join(homedir(), ".docker/cli-plugins/docker-compose"))).toBe(true);
    expect(otherCommandIsVisible(path.join(homedir(), ".docker/private-cache/metadata.json"))).toBe(false);
    expect(dockerIsVisible(path.join(homedir(), ".config/cloud/credentials"))).toBe(false);
  });

  it("treats current sandbox temp roots and common /tmp aliases as visible", () => {
    const isVisible = createSandboxVisibilityMatcher({
      repoRoot: "/workspace/repo",
      cwd: "/workspace/repo",
      profile: makeProfile(),
      config: makeConfig(),
    });

    for (const tempRoot of getSandboxTempPaths()) {
      expect(isVisible(path.join(tempRoot, "uv-temp-file"))).toBe(true);
    }
    expect(isVisible(path.join("/tmp", "xdg-cache", "uv"))).toBe(true);
    expect(isVisible(path.join("/private/tmp", "xdg-cache", "uv"))).toBe(true);
  });
});

describe("detectExternalPaths", () => {
  it("does not prompt for paths made visible through current sandbox config/profile binds", async () => {
    const cwd = await makeTempDir("pi-visible-cwd-");
    const repoRoot = cwd;
    const extraDir = await makeTempDir("pi-visible-extra-");
    const extraFile = path.join(extraDir, "notes.txt");
    await mkdir(extraDir, { recursive: true });
    await writeFile(extraFile, "hello", "utf8");

    const profile = makeProfile({ roBinds: [extraDir] });
    const config = makeConfig();

    const externals = detectExternalPaths(
      `cat ${extraFile}`,
      cwd,
      profile,
      config,
      () => repoRoot,
    );

    expect(externals).toEqual([]);
  });

  it("still prompts for existing out-of-scope external paths", async () => {
    const cwd = await makeTempDir("pi-visible-cwd-");
    const repoRoot = cwd;
    const externalDir = await mkdtemp(path.join(homedir(), ".pi-hidden-extra-"));
    tempPaths.push(externalDir);
    const externalFile = path.join(externalDir, "notes.txt");
    await mkdir(externalDir, { recursive: true });
    await writeFile(externalFile, "hello", "utf8");

    const externals = detectExternalPaths(
      `cat ${externalFile}`,
      cwd,
      makeProfile(),
      makeConfig(),
      () => repoRoot,
    );

    expect(externals).toHaveLength(1);
    expect(externals[0]?.path).toBe(path.resolve(externalFile));
  });
});
