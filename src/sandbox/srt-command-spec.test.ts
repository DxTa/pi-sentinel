import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { EXTENSION_ROOT } from "../extension-config.js";
import type { SandboxConfig, ResolvedSandboxProfile, UnmaskedPath } from "./types.js";
import {
  buildSrtCommandSpec,
  buildSrtCommandSpecAsync,
} from "./srt-command-spec.js";
import { buildSrtRuntimeConfig } from "./srt-runtime-config.js";
import { canonicalPath } from "./sandbox-visible-paths.js";

const require = createRequire(import.meta.url);
const tempPaths: string[] = [];
const originalHome = process.env.HOME;

beforeEach(async () => {
  const isolatedHome = await mkdtemp(path.join(tmpdir(), "pi-srt-spec-home-"));
  tempPaths.push(isolatedHome);
  process.env.HOME = isolatedHome;
});

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function makeProfile(overrides: Partial<ResolvedSandboxProfile> = {}): ResolvedSandboxProfile {
  return {
    name: "online-dev",
    network: true,
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
    backend: "srt",
    profiles: {},
    defaultProfile: "online-dev",
    roBinds: [],
    rwBinds: [],
    ...overrides,
  };
}

const privateScriptPath = path.join(
  "/opt",
  "agent-tools",
  "agent-semantic-search.mjs",
);

describe("buildSrtCommandSpec", () => {
  it("fails closed when async filesystem preparation exceeds its budget", async () => {
    const repoRoot = await makeTempDir("pi-srt-spec-budget-");

    await expect(buildSrtCommandSpecAsync({
      command: "echo ok",
      cwd: repoRoot,
      repoRoot,
      sandboxConfig: makeConfig(),
      profile: makeProfile(),
    }, 0)).rejects.toThrow(/exceeded 0 ms/i);
  });

  it("builds immutable per-command spec with resolved binds and network plan", { timeout: 30_000 }, async () => {
    const repoRoot = await makeTempDir("pi-srt-spec-repo-");
    const cwd = path.join(repoRoot, "workspace");
    const sharedDir = path.join(repoRoot, "shared-ro");
    const writableDir = path.join(repoRoot, "shared-rw");
    await mkdir(cwd, { recursive: true });
    await mkdir(sharedDir, { recursive: true });
    await mkdir(writableDir, { recursive: true });
    await writeFile(path.join(sharedDir, "a.txt"), "a", "utf8");
    await writeFile(path.join(writableDir, "b.txt"), "b", "utf8");

    const profile = makeProfile({
      roBinds: ["shared-ro"],
      rwBinds: ["shared-rw"],
      maskedPaths: ["**/.env"],
      env: { allow: [], deny: ["*_TOKEN"] },
      resourceLimits: { pids: 64, tmpfsSize: "64m" },
    });
    const config = makeConfig({ roBinds: ["shared-ro"], rwBinds: ["shared-rw"] });
    const unmaskedPaths: UnmaskedPath[] = [{ path: path.join(repoRoot, ".env"), writable: false }];

    const spec = buildSrtCommandSpec({
      command: "curl https://api.github.com/repos",
      cwd,
      repoRoot,
      sandboxConfig: config,
      profile,
      unifiedConfig: {
        network: {
          enabled: true,
          unknownDomains: "ask",
          allowedDomains: ["github.com"],
          deniedDomains: ["blocked.example.com"],
        },
      },
      approvedDomains: ["api.github.com"],
      unmaskedPaths,
      secretEnv: { GH_TOKEN: "ignored-value" },
    });

    expect(spec.command).toBe("curl https://api.github.com/repos");
    expect(spec.cwd).toBe(canonicalPath(cwd));
    expect(spec.repoRoot).toBe(canonicalPath(repoRoot));
    expect(spec.profileName).toBe("online-dev");
    expect(spec.networkEnabled).toBe(true);
    expect(spec.allowDocker).toBe(false);
    expect(spec.roBinds).toEqual([canonicalPath(sharedDir)]);
    expect(spec.rwBinds).toEqual([canonicalPath(writableDir)]);
    expect(spec.maskedPaths).toEqual(["**/.env"]);
    expect(spec.unmaskedPaths).toEqual([{ path: canonicalPath(unmaskedPaths[0]!.path), writable: false }]);
    expect(spec.secretEnvNames).toEqual(["GH_TOKEN"]);
    expect(spec.envDenyPatterns).toEqual(["*_TOKEN"]);
    expect(spec.resourceLimits).toEqual({ pids: 64, tmpfsSize: "64m" });
    expect(spec.maskedShimPlan.maskedFilePaths).toEqual([]);
    expect(spec.maskedShimPlan.maskedDenyPaths.every((maskedPath) => maskedPath.endsWith("/.env"))).toBe(true);
    expect(spec.maskedShimPlan.shimCommands).toEqual([]);
    expect((spec as any).execShimPlan).toEqual(
      process.platform === "darwin"
        ? { git: "/Library/Developer/CommandLineTools/usr/bin/git" }
        : {},
    );
    const srtPackageRoot = path.dirname(require.resolve("@anthropic-ai/sandbox-runtime/package.json"));
    const seccompArch = process.arch === "arm64" ? "arm64" : "x64";
    const applySeccompPath = path.join(
      srtPackageRoot,
      "vendor",
      "seccomp",
      seccompArch,
      "apply-seccomp",
    );

    expect(spec.visibleReadPaths).toEqual(expect.arrayContaining([
      canonicalPath(repoRoot),
      canonicalPath(cwd),
      canonicalPath(sharedDir),
      canonicalPath(writableDir),
      canonicalPath("/usr"),
      canonicalPath("/bin"),
      canonicalPath("/etc/gitconfig"),
      canonicalPath(srtPackageRoot),
    ]));
    expect(spec.visibleReadPaths.some((visiblePath) =>
      canonicalPath(applySeccompPath).startsWith(`${visiblePath}/`),
    )).toBe(true);
    expect(spec.runtimeReadAllowPaths).toEqual(expect.arrayContaining([
      canonicalPath(repoRoot),
      canonicalPath(cwd),
      canonicalPath(sharedDir),
      canonicalPath(writableDir),
      canonicalPath("/usr"),
      canonicalPath("/bin"),
      canonicalPath("/etc/gitconfig"),
      canonicalPath(srtPackageRoot),
    ]));
    const homePath = canonicalPath(process.env.HOME ?? path.join(tmpdir(), "home"));
    expect(spec.visibleReadPaths).not.toContain(homePath);
    expect(spec.runtimeReadAllowPaths).not.toContain(homePath);
    expect(spec.networkPlan).toEqual({
      mode: "runtime-filtered",
      requiresOuterPrompt: true,
      unmatchedHostAction: "deny",
      config: {
        allowedDomains: ["github.com", "api.github.com"],
        deniedDomains: ["blocked.example.com"],
        strictAllowlist: true,
      },
    });
  });

  it("omits missing optional binds from sync and async specs", { timeout: 30_000 }, async () => {
    const repoRoot = await makeTempDir("pi-srt-spec-stale-bind-");
    process.env.HOME = repoRoot;
    const existingRoBind = path.join(repoRoot, "existing-ro");
    const existingRwBind = path.join(repoRoot, "existing-rw");
    const missingBind = path.join(repoRoot, "missing");
    await mkdir(existingRoBind, { recursive: true });
    await mkdir(existingRwBind, { recursive: true });

    const input = {
      command: "echo ok",
      cwd: repoRoot,
      repoRoot,
      sandboxConfig: makeConfig({
        roBinds: [existingRoBind, missingBind],
        rwBinds: [existingRwBind, missingBind],
      }),
      profile: makeProfile(),
    };

    const specs = [
      buildSrtCommandSpec(input),
      await buildSrtCommandSpecAsync(input),
    ];

    for (const spec of specs) {
      expect(spec.roBinds).toEqual([canonicalPath(existingRoBind)]);
      expect(spec.rwBinds).toEqual([canonicalPath(existingRwBind)]);
      expect(spec.visibleReadPaths).not.toContain(canonicalPath(missingBind));
      expect(spec.runtimeReadAllowPaths).not.toContain(canonicalPath(missingBind));
    }
  });

  it("includes runtime package roots in async specs", async () => {
    const repoRoot = await makeTempDir("pi-srt-spec-runtime-roots-");
    const spec = await buildSrtCommandSpecAsync({
      command: "echo ok",
      cwd: repoRoot,
      repoRoot,
      sandboxConfig: makeConfig(),
      profile: makeProfile(),
    });
    const srtPackageRoot = path.dirname(require.resolve("@anthropic-ai/sandbox-runtime/package.json"));

    expect(spec.runtimeReadAllowPaths).toEqual(expect.arrayContaining([
      canonicalPath(EXTENSION_ROOT),
      canonicalPath(srtPackageRoot),
    ]));
  });

  it("filters approved unmasked paths out of the masked shim plan", async () => {
    const repoRoot = await makeTempDir("pi-srt-spec-filter-");
    const cwd = repoRoot;
    const envPath = path.join(repoRoot, ".env");
    await writeFile(envPath, "SECRET=1\n", "utf8");

    const spec = buildSrtCommandSpec({
      command: "cat .env",
      cwd,
      repoRoot,
      sandboxConfig: makeConfig(),
      profile: makeProfile({ maskedPaths: ["**/.env"] }),
      unmaskedPaths: [{ path: envPath, writable: false }],
    });

    expect(spec.maskedShimPlan.maskedFilePaths).toEqual([]);
    expect(spec.maskedShimPlan.maskedDenyPaths).toEqual([]);
    expect(spec.maskedShimPlan.shimCommands).toEqual([]);
  });

  it("does not trust external helper paths", async () => {
    const repoRoot = await makeTempDir("pi-srt-spec-semantic-search-");
    process.env.HOME = repoRoot;
    const envPath = path.join(repoRoot, ".env");
    await writeFile(envPath, "SECRET=1\n", "utf8");
    const profile = makeProfile({ maskedPaths: ["**/.env"] });

    const spec = buildSrtCommandSpec({
      command: `node "${privateScriptPath}" search --catalog agents --query "test" --top-k 5`,
      cwd: repoRoot,
      repoRoot,
      sandboxConfig: makeConfig(),
      profile,
    });

    expect(spec.maskedShimPlan.maskedDenyPaths).toEqual([canonicalPath(envPath)]);
    expect(spec.runtimeReadAllowPaths).toContain(canonicalPath(repoRoot));
    expect(buildSrtRuntimeConfig(spec).filesystem.allowWrite).not.toEqual([]);
  });
});
