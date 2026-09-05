import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  extractExternalPathsFromBashCommand,
  extractTokensForPathRules,
} from "./bash-path-extractor";

const FALLBACK_ENV = "PI_PERMISSION_SYSTEM_DISABLE_TREE_SITTER";

afterEach(() => {
  delete process.env[FALLBACK_ENV];
});

describe("bash path extractor tokenizer fallback", () => {
  it("extracts path-rule tokens without tree-sitter runtime", async () => {
    process.env[FALLBACK_ENV] = "1";

    const tokens = await extractTokensForPathRules(
      "grep -e '^/tmp' ./src/file.ts .env && cat ../notes.md",
    );

    expect(tokens).toEqual(["./src/file.ts", ".env", "../notes.md"]);
  });

  it("extracts external paths without tree-sitter runtime", async () => {
    process.env[FALLBACK_ENV] = "1";
    const cwd = path.join("/tmp", "project");

    const paths = await extractExternalPathsFromBashCommand(
      "cat ../secret.txt && sed -e 's/x/y/' ~/global.conf > ./local.txt",
      cwd,
    );

    expect(paths).toContain(path.normalize(path.join("/tmp", "secret.txt")));
    expect(paths).toContain(path.normalize(path.join(process.env.HOME || "", "global.conf")));
    expect(paths).not.toContain(path.normalize(path.join(cwd, "local.txt")));
  });
});
