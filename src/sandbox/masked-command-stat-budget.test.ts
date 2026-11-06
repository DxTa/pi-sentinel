import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  // Only the masked file's own checks are slow; the scan's root check stays fast.
  const slowFor = async <T>(path: unknown, promise: Promise<T>): Promise<T> => {
    if (String(path).endsWith(".env")) await new Promise((resolve) => setTimeout(resolve, 300));
    return promise;
  };
  return {
    ...actual,
    stat: (path: Parameters<typeof actual.stat>[0], ...rest: unknown[]) =>
      slowFor(path, (actual.stat as (...values: unknown[]) => Promise<never>)(path, ...rest)),
    lstat: (path: Parameters<typeof actual.lstat>[0], ...rest: unknown[]) =>
      slowFor(path, (actual.lstat as (...values: unknown[]) => Promise<never>)(path, ...rest)),
  };
});

import { buildMaskedCommandShimPlanAsync } from "./masked-command-shim.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const profile = {
  name: "online-dev",
  network: true,
  allowDocker: false,
  roBinds: [],
  rwBinds: [],
  env: { allow: [], deny: [] },
  maskedPaths: ["**/.env"],
} as never;

describe("masked path checks after the scan", () => {
  it("keeps a masked file denied when its check runs out of the scan budget", async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-stat-budget-"));
    dirs.push(root);
    writeFileSync(join(root, ".env"), "TOKEN=x\n", "utf8");

    const plan = await buildMaskedCommandShimPlanAsync("echo ok", profile, root, {
      deadline: Date.now() + 150,
      maxScanDurationMs: 150,
    });

    expect(plan.maskedDenyPaths).toEqual([expect.stringContaining(".env")]);
  });
});
