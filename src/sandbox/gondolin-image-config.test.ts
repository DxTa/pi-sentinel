import { symlinkSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it, vi } from "vitest";

const imageManifests = vi.hoisted(() => new Map<string, { config: Record<string, unknown> }>([
  ["94877d6e-4ba5-5f37-baa7-be5b90aabd7e", {
    config: {
      arch: "aarch64",
      oci: { image: `ghcr.io/astral-sh/uv@sha256:${"a".repeat(64)}` },
    },
  }],
  ["3cd7a864-f023-5a35-9db1-39a1be5bdcca", { config: { arch: "x86_64", distro: "alpine" } }],
]));

vi.mock("@earendil-works/gondolin", async () => {
  const actual = await vi.importActual<typeof import("@earendil-works/gondolin")>("@earendil-works/gondolin");
  return {
    ...actual,
    getImageObjectDirectory: (image: string) => image,
    loadAssetManifest: (directory: string) => imageManifests.get(directory),
  };
});
import {
  GONDOLIN_IMAGE_LOCK_SCHEMA,
  buildGondolinWorkspace,
  missingGondolinBuildCommands,
  parseGondolinImageLock,
  resolveGondolinBuildPath,
  resolveGondolinImageLibc,
  resolveGondolinImageUvTarget,
  planGondolinWorkspace,
  readGondolinImageLock,
  resolveWorkspaceGondolinImage,
  serializeGondolinImageLock,
  writeGondolinBuildConfig,
} from "./gondolin-image-config.js";

describe("Gondolin image metadata paths", () => {
  it("rejects symlinked metadata directories and oversized lock files", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-paths-"));
    const outside = await mkdtemp(join(tmpdir(), "gondolin-image-outside-"));
    try {
      await mkdir(join(root, ".pi"));
      symlinkSync(outside, join(root, ".pi", "gondolin"));
      await expect(writeGondolinBuildConfig(root, {} as never)).rejects.toThrow(/symlink|directory/i);

      await rm(join(root, ".pi", "gondolin"), { recursive: true, force: true });
      await mkdir(join(root, ".pi", "gondolin"), { recursive: true });
      await writeFile(join(root, ".pi", "gondolin", "image-lock.json"), "x".repeat(70_000));
      expect(() => readGondolinImageLock(root)).toThrow(/size|large|invalid/i);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("rejects special lock files without opening them", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-fifo-"));
    try {
      await mkdir(join(root, ".pi", "gondolin", "image-lock.json"), { recursive: true });
      expect(() => readGondolinImageLock(root)).toThrow(/regular|special|invalid/i);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("resolveGondolinBuildPath", () => {
  it("accepts absolute trusted directories but rejects workspace-controlled paths", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "gondolin-build-path-workspace-"));
    try {
      expect(resolveGondolinBuildPath("/usr/bin:/usr/sbin", workspace)).toBe("/usr/bin:/usr/sbin");
      expect(() => resolveGondolinBuildPath(`${workspace}/bin:/usr/bin`, workspace)).toThrow(/workspace|trusted/i);
      expect(() => resolveGondolinBuildPath("relative:/usr/bin", workspace)).toThrow(/absolute|trusted/i);
      expect(() => resolveGondolinBuildPath("/tmp:/usr/bin", workspace)).toThrow(/world|trusted/i);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

describe("missingGondolinBuildCommands", () => {
  it("reports required host tools from PATH", () => {
    expect(missingGondolinBuildCommands("/empty")).toEqual(["mke2fs", "lz4", "cpio", "find"]);
  });
});

describe("resolveGondolinImageUvTarget", () => {
  it("fails closed when an OCI rootfs ABI is not identified", () => {
    expect(resolveGondolinImageLibc({ distro: "alpine", oci: { image: "registry.example/alpine:latest" } })).toBeUndefined();
    expect(resolveGondolinImageLibc({ distro: "alpine" })).toBe("musl");
  });

  it("derives the Python ABI target from the verified guest image", () => {
    expect(resolveGondolinImageUvTarget("94877d6e-4ba5-5f37-baa7-be5b90aabd7e")).toBe("aarch64-unknown-linux-gnu");
    expect(resolveGondolinImageUvTarget("3cd7a864-f023-5a35-9db1-39a1be5bdcca")).toBe("x86_64-unknown-linux-musl");
  });
});

describe("planGondolinWorkspace", () => {
  it("ignores symlinked, directory, and oversized metadata candidates", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-metadata-"));
    const outside = await mkdtemp(join(tmpdir(), "gondolin-image-metadata-outside-"));
    try {
      await writeFile(join(outside, "package.json"), "{}");
      symlinkSync(join(outside, "package.json"), join(root, "package.json"));
      expect(planGondolinWorkspace(root).detected).not.toContain("node");
      await rm(join(root, "package.json"), { force: true });
      await mkdir(join(root, "package.json"));
      expect(planGondolinWorkspace(root).detected).not.toContain("node");
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("uses the requested guest architecture when planning a future project", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-arch-"));
    try {
      await writeFile(join(root, "pyproject.toml"), "[project]\nname='demo'\n");
      expect(planGondolinWorkspace(root, "aarch64").config.arch).toBe("aarch64");
      expect(planGondolinWorkspace(root, "x86_64").config.arch).toBe("x86_64");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("detects common runtimes from metadata without scanning source files", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-plan-"));
    try {
      await mkdir(join(root, "src"));
      await writeFile(join(root, "package.json"), '{"name":"demo"}\n');
      await writeFile(join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
      await writeFile(join(root, "pyproject.toml"), "[project]\nname='demo'\n");
      await writeFile(join(root, ".env"), "SECRET=must-not-be-read\n");
      await writeFile(join(root, "src", "auth-handler.ts"), "credentials = 'source'\n");

      const plan = planGondolinWorkspace(root);

      expect(plan.detected).toEqual(["node", "python"]);
      expect(plan.config.distro).toBe("alpine");
      expect(plan.config.alpine?.rootfsPackages).toEqual(expect.arrayContaining(["nodejs", "npm", "python3", "uv"]));
      expect(plan.planDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(plan.configPath).toBe(join(root, ".pi", "gondolin", "build-config.json"));
      expect(plan.lockPath).toBe(join(root, ".pi", "gondolin", "image-lock.json"));
      expect(JSON.stringify(plan)).not.toContain("SECRET");
      expect(JSON.stringify(plan)).not.toContain("credentials");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("buildGondolinWorkspace", () => {
  it("rejects an aborted build before invoking the builder", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-abort-"));
    try {
      const controller = new AbortController();
      controller.abort();
      let called = false;
      await expect(buildGondolinWorkspace(root, {
        signal: controller.signal,
        dependencies: { buildAssets: async () => { called = true; throw new Error("unexpected"); } },
      })).rejects.toThrow(/aborted/i);
      expect(called).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects concurrent builds for one workspace", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-concurrent-"));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    try {
      const dependencies = {
        buildAssets: async (_config: any, options: any) => {
          await gate;
          await writeFile(join(options.outputDir, "manifest.json"), "{}");
          return { outputDir: options.outputDir, manifestPath: join(options.outputDir, "manifest.json"), manifest: {} as never };
        },
        verifyAssets: () => true,
        importImageFromDirectory: (assetDir: string) => ({ buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca", arch: "x86_64", assetDir, created: true }),
        loadAssetManifest: () => ({ buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca", config: { arch: "x86_64" } } as never),
        getAssetVersion: () => "v0.12.0",
      };
      const first = buildGondolinWorkspace(root, { dependencies: dependencies as never });
      await expect(buildGondolinWorkspace(root, { dependencies: dependencies as never })).rejects.toThrow(/already in progress/i);
      release();
      await first;
    } finally {
      release?.();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("imports and locks verified build output without post-build commands", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-build-"));
    try {
      const plan = planGondolinWorkspace(root);
      let buildConfig: unknown;
      const result = await buildGondolinWorkspace(root, {
        plan,
        dependencies: {
          buildAssets: async (config, options) => {
            buildConfig = config;
            await writeFile(join(options.outputDir, "manifest.json"), JSON.stringify({ buildId: "unused" }));
            return { outputDir: options.outputDir, manifestPath: join(options.outputDir, "manifest.json"), manifest: {} as never };
          },
          verifyAssets: () => true,
          importImageFromDirectory: (assetDir) => ({ buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca", arch: "x86_64", assetDir, created: true }),
          loadAssetManifest: () => ({ buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca", config: { arch: "x86_64" } } as never),
          getAssetVersion: () => "v0.12.0",
        },
      });

      expect(buildConfig).toMatchObject({ distro: "alpine" });
      expect(buildConfig).not.toHaveProperty("postBuild");
      expect(result.buildId).toBe("3cd7a864-f023-5a35-9db1-39a1be5bdcca");
      expect(readGondolinImageLock(root)?.buildId).toBe(result.buildId);
      expect(JSON.parse(await readFile(plan.configPath, "utf8")).postBuild).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("parseGondolinImageLock", () => {
  it("accepts only exact verified build metadata", () => {
    const lock = parseGondolinImageLock({
      schema: GONDOLIN_IMAGE_LOCK_SCHEMA,
      buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca",
      manifestSha256: "a".repeat(64),
      configSha256: "b".repeat(64),
      arch: "x86_64",
      gondolinVersion: "0.12.0",
    });

    expect(lock.buildId).toBe("3cd7a864-f023-5a35-9db1-39a1be5bdcca");
    expect(JSON.parse(serializeGondolinImageLock(lock))).toEqual(lock);
  });

  it("rejects a lock whose verified image is unavailable", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-resolve-"));
    try {
      await mkdir(join(root, ".pi", "gondolin"), { recursive: true });
      await writeFile(join(root, ".pi", "gondolin", "image-lock.json"), serializeGondolinImageLock({
        schema: GONDOLIN_IMAGE_LOCK_SCHEMA,
        buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca",
        manifestSha256: "a".repeat(64),
        configSha256: "b".repeat(64),
        arch: "x86_64",
        gondolinVersion: "0.12.0",
      }));
      expect(() => resolveWorkspaceGondolinImage(root)).toThrow(/unavailable|manifest|assets|incomplete/i);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("writes build config and reads a workspace lock without exposing host paths", async () => {
    const root = await mkdtemp(join(tmpdir(), "gondolin-image-lock-"));
    try {
      const plan = planGondolinWorkspace(root);
      await writeGondolinBuildConfig(root, plan.config);
      expect(JSON.parse(await readFile(plan.configPath, "utf8"))).toEqual(plan.config);
      await writeFile(plan.lockPath, serializeGondolinImageLock({
        schema: GONDOLIN_IMAGE_LOCK_SCHEMA,
        buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca",
        manifestSha256: "a".repeat(64),
        configSha256: "b".repeat(64),
        arch: "x86_64",
        gondolinVersion: "0.12.0",
      }));
      expect(readGondolinImageLock(root)?.buildId).toBe("3cd7a864-f023-5a35-9db1-39a1be5bdcca");
      expect(readGondolinImageLock(root)).not.toHaveProperty("workspaceRoot");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it.each([
    { buildId: "latest" },
    { buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca", manifestSha256: "bad" },
    { buildId: "3cd7a864-f023-5a35-9db1-39a1be5bdcca", manifestSha256: "a".repeat(64), arch: "arm" },
  ])("rejects invalid lock %#", (value) => {
    expect(() => parseGondolinImageLock({
      schema: GONDOLIN_IMAGE_LOCK_SCHEMA,
      configSha256: "b".repeat(64),
      gondolinVersion: "0.12.0",
      ...value,
    })).toThrow();
  });
});
