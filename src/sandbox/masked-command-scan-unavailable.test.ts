import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { buildMaskedCommandShimPlan } from "./masked-command-shim.js";

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

describe("buildMaskedCommandShimPlan scan failures", () => {
  it("reports an unscannable root instead of throwing, so the caller can ask the user", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-unscannable-"));
    dirs.push(root);
    for (const name of ["s1", "s2", "s3"]) {
      mkdirSync(join(root, name));
      writeFileSync(join(root, name, ".env"), "TOKEN=x\n", "utf8");
    }

    const plan = buildMaskedCommandShimPlan("ls", profile, root, { maxEntries: 1 });

    expect(plan.unscannedRoots.some((entry) => basename(entry.root) === basename(root))).toBe(true);
    expect(plan.unscannedRoots[0]?.reason).toMatch(/exceeded/);
  });
});
