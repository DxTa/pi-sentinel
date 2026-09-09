import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  buildMaskedCommandShimPlan,
  buildMaskedCommandShimPlanAsync,
} from "./masked-command-shim.js";
import type { SandboxProfile } from "./types.js";

const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function makeProfile(): SandboxProfile {
  return {
    network: false,
    allowDocker: false,
    roBinds: [],
    rwBinds: [],
    env: { allow: [], deny: [] },
    maskedPaths: ["**/.env", "**/*.pem"],
  };
}

describe("buildMaskedCommandShimPlan", () => {
  it("enables direct reader shims for masked file reads", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    const envPath = path.join(cwd, ".env");
    await writeFile(envPath, "SECRET=1\n", "utf8");

    expect(buildMaskedCommandShimPlan("cat .env", makeProfile(), cwd)).toEqual({
      maskedFilePaths: [envPath],
      maskedDenyPaths: [envPath],
      shimCommands: ["cat"],
    });
    expect(buildMaskedCommandShimPlan("head .env", makeProfile(), cwd).shimCommands).toEqual(["head"]);
    expect(buildMaskedCommandShimPlan("tail .env", makeProfile(), cwd).shimCommands).toEqual(["tail"]);
    expect(buildMaskedCommandShimPlan("grep masked .env", makeProfile(), cwd).shimCommands).toEqual(["grep"]);
    expect(buildMaskedCommandShimPlan("rg masked .env", makeProfile(), cwd).shimCommands).toEqual(["rg"]);
  });

  it("uses profile-level concrete deny paths even when command does not use supported reader", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    const envPath = path.join(cwd, ".env");
    await writeFile(envPath, "SECRET=1\n", "utf8");

    expect(buildMaskedCommandShimPlan("sh read-secret.sh", makeProfile(), cwd)).toEqual({
      maskedFilePaths: [],
      maskedDenyPaths: [envPath],
      shimCommands: [],
    });
  });

  it("skips dependency/build dirs to respect scan cap", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    const nestedDir = path.join(cwd, "apps", "web");
    const dependencyDir = path.join(cwd, "node_modules", "pkg");
    await mkdir(nestedDir, { recursive: true });
    await mkdir(dependencyDir, { recursive: true });
    const nestedEnv = path.join(nestedDir, ".env");
    const dependencyPem = path.join(dependencyDir, "private.pem");
    await writeFile(nestedEnv, "SECRET=1\n", "utf8");
    await writeFile(dependencyPem, "SECRET=2\n", "utf8");

    const plan = buildMaskedCommandShimPlan("echo ok", makeProfile(), cwd);
    expect(plan.maskedFilePaths).toEqual([]);
    expect(plan.maskedDenyPaths).toEqual(expect.arrayContaining([nestedEnv, dependencyPem]));
    expect(plan.maskedDenyPaths).toHaveLength(2);
    expect(plan.shimCommands).toEqual([]);
  });

  it("does not follow symlink loops while scanning", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    const envPath = path.join(cwd, ".env");
    await writeFile(envPath, "SECRET=1\n", "utf8");
    await symlink(cwd, path.join(cwd, "loop"));

    expect(buildMaskedCommandShimPlan("echo ok", makeProfile(), cwd)).toEqual({
      maskedFilePaths: [],
      maskedDenyPaths: [envPath],
      shimCommands: [],
    });
  });

  it("fails closed when scan limit is exceeded", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    await writeFile(path.join(cwd, "a.txt"), "a", "utf8");
    await writeFile(path.join(cwd, "b.txt"), "b", "utf8");

    expect(() =>
      buildMaskedCommandShimPlan("echo ok", makeProfile(), cwd, { maxEntries: 1 }),
    ).toThrow(/masked file scan failed/i);
  });

  it("fails closed when scan duration budget is exceeded", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    await writeFile(path.join(cwd, "secret.pem"), "SECRET=1\n", "utf8");

    expect(() =>
      buildMaskedCommandShimPlan("echo ok", makeProfile(), cwd, {
        maxScanDurationMs: 0,
      }),
    ).toThrow(/masked file scan failed.*exceeded 0 ms/i);
  });

  it("skips system temp roots before scanning", async () => {
    await expect(
      buildMaskedCommandShimPlanAsync("echo ok", makeProfile(), tmpdir(), {
        deadline: Date.now(),
        maxScanDurationMs: 0,
      }),
    ).resolves.toEqual({
      maskedFilePaths: [],
      maskedDenyPaths: [],
      shimCommands: [],
    });
  });

  it("skips workspace scanning when requested but still detects explicit masked paths", async () => {
    const cwd = await makeTempDir("pi-mask-shim-trusted-");
    const envPath = path.join(cwd, ".env");
    await writeFile(path.join(cwd, "a.txt"), "a", "utf8");
    await writeFile(path.join(cwd, "b.txt"), "b", "utf8");
    await writeFile(envPath, "SECRET=1\n", "utf8");

    expect(
      buildMaskedCommandShimPlan("echo ok", makeProfile(), cwd, {
        maxEntries: 1,
        skipWorkspaceScan: true,
      }),
    ).toEqual({
      maskedFilePaths: [],
      maskedDenyPaths: [],
      shimCommands: [],
    });
    expect(
      buildMaskedCommandShimPlan("cat .env", makeProfile(), cwd, {
        maxEntries: 1,
        skipWorkspaceScan: true,
      }),
    ).toEqual({
      maskedFilePaths: [envPath],
      maskedDenyPaths: [envPath],
      shimCommands: ["cat"],
    });
  });

  it("scans runtime-readable config-like roots for generic masked patterns", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    const configRoot = await makeTempDir("pi-mask-config-");
    const pemPath = path.join(configRoot, "pi-mask-audit", "secret.pem");
    await mkdir(path.dirname(pemPath), { recursive: true });
    await writeFile(pemPath, "TOPSECRET\n", "utf8");

    expect(
      buildMaskedCommandShimPlan("echo ok", makeProfile(), cwd, {
        scanRoots: [configRoot],
      }),
    ).toEqual({
      maskedFilePaths: [],
      maskedDenyPaths: [pemPath],
      shimCommands: [],
    });
  });

  it("scans readable external bind roots for masked secrets", async () => {
    const cwd = await makeTempDir("pi-mask-shim-");
    const bindRoot = await makeTempDir("pi-mask-bind-");
    const bindPem = path.join(bindRoot, "private.pem");
    await writeFile(bindPem, "SECRET=3\n", "utf8");

    expect(
      buildMaskedCommandShimPlan("echo ok", makeProfile(), cwd, {
        scanRoots: [bindRoot],
      }),
    ).toEqual({
      maskedFilePaths: [],
      maskedDenyPaths: [bindPem],
      shimCommands: [],
    });
  });
});
