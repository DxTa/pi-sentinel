import path from "node:path";
import { tmpdir } from "node:os";

import { afterEach, describe, expect, it } from "vitest";

import {
  extractExternalPathsFromBashCommand,
  extractExternalWritePathsFromBashCommand,
  extractTokensForPathRules,
} from "./bash-path-extractor";

const FALLBACK_ENV = "PI_PERMISSION_SYSTEM_DISABLE_TREE_SITTER";

afterEach(() => {
  delete process.env[FALLBACK_ENV];
});

describe("bash path extractor path candidates", () => {
  it("ignores sed substitution scripts while preserving file arguments", async () => {
    const envPath = "/tmp/project/.env.local";

    await expect(extractTokensForPathRules(
      `cat ${envPath} | sed 's/=/: /'`,
    )).resolves.toEqual([envPath]);
  });

  it("joins path fragments adjacent to single-quoted text", async () => {
    const path = "/tmp/project/.env.local";
    await expect(extractTokensForPathRules("cat /tmp/project/.en'v.local'"))
      .resolves.toEqual([path]);
  });

  it("preserves explicit root paths and paths in option values", async () => {
    await expect(extractTokensForPathRules("ls / && tool --config=/etc/hosts"))
      .resolves.toEqual(["/", "/etc/hosts"]);
  });
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


describe("external Bash write path extraction", () => {
  it("selects output redirection targets, not input paths", async () => {
    const root = tmpdir();
    const cwd = path.join(root, "project");
    const input = path.join(root, "shared", "input.txt");
    const output = path.join(root, "shared", "output.txt");

    await expect(
      extractExternalWritePathsFromBashCommand("cat " + input + " > " + output, cwd),
    ).resolves.toEqual([path.normalize(output)]);
  });

  it("ignores input redirects and redirection text inside strings", async () => {
    const root = tmpdir();
    const cwd = path.join(root, "project");
    const input = path.join(root, "shared", "input.txt");
    const output = path.join(root, "shared", "not-an-output.txt");
    const command = "printf %s ' > " + output + "' < " + input;

    await expect(extractExternalWritePathsFromBashCommand(command, cwd)).resolves.toEqual([]);
  });
  it.each([
    ["ANSI-C", "$'/tmp/pi-ansi-c-output.txt'"],
    ["translated", '$"/tmp/pi-translated-output.txt"'],
  ])("rejects %s-quoted output redirect targets", async (_label, target) => {
    await expect(
      extractExternalWritePathsFromBashCommand("echo value > " + target, tmpdir()),
    ).rejects.toThrow(/unsupported.*redirect/i);
  });

  it("fails closed when the Bash parser is disabled", async () => {
    process.env[FALLBACK_ENV] = "1";
    const output = path.join(tmpdir(), "outside.txt");

    await expect(
      extractExternalWritePathsFromBashCommand("echo value > " + output, path.join(tmpdir(), "project")),
    ).resolves.toEqual([]);
  });
});
