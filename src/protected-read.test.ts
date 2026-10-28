import { homedir } from "node:os";
import { join } from "node:path";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import { afterAll, describe, expect, it } from "vitest";

import { extractTokensForPathRules } from "./handlers/gates/bash-path-extractor";
import { isProtectedCredentialReadPath, prepareApprovedTarget, protectedBashReadPaths, protectedWriteRefusal } from "./protected-read";
import { DEFAULT_MASKED_PATTERNS } from "./sandbox/masked-file-gate";

// macOS tmpdir() is a symlink into /private; the code under test returns canonical paths.
const cwd = realpathSync.native(mkdtempSync(join(tmpdir(), "pi-protected-read-workspace-")));
const sshConfig = join(homedir(), ".ssh", "config");
const appConfig = join(homedir(), ".config", "app", "settings.json");
const awsCredentials = join(homedir(), ".aws", "credentials");
const certPath = join(cwd, "server.pem");
const credentialsJson = join(cwd, "credentials.json");
const envPath = join(cwd, ".env");
const envLocalPath = join(cwd, ".env.local");
const envExamplePath = join(cwd, ".env.example");

mkdirSync(join(cwd, ".ssh"));
writeFileSync(join(cwd, "notes.txt"), "not a secret", "utf8");
writeFileSync(certPath, "synthetic-private-key", "utf8");
writeFileSync(credentialsJson, '{"token":"synthetic"}', "utf8");
writeFileSync(envPath, "TOKEN=synthetic", "utf8");
writeFileSync(envLocalPath, "TOKEN=synthetic", "utf8");
writeFileSync(envExamplePath, "TOKEN=placeholder", "utf8");
symlinkSync(join(cwd, "notes.txt"), join(cwd, ".ssh", "id_ed25519"));

afterAll(() => rmSync(cwd, { recursive: true, force: true }));

describe("isProtectedCredentialReadPath", () => {
  it.each([
    sshConfig,
    appConfig,
    awsCredentials,
    "$HOME/.aws/credentials",
    "~/.ssh/id_ed25519",
    "~/.config/gh/hosts.yml",
    join(homedir(), ".kube", "config"),
    join(homedir(), ".docker", "config.json"),
    certPath,
    credentialsJson,
  ])("protects %s", (path) => expect(isProtectedCredentialReadPath(path, cwd)).toBe(true));

  it.each([
    "src/index.ts",
    "/etc/hosts",
    "/tmp/unrelated/.env",
    join(homedir(), ".sshx", "file"),
    join(homedir(), ".configuration"),
    join(homedir(), ".ssh", "..", "notes.txt"),
    envPath,
    envExamplePath,
    join(cwd, ".ssh", "id_ed25519"),
  ])("does not protect %s as a generic credential path", (path) =>
    expect(isProtectedCredentialReadPath(path, cwd)).toBe(false));
});

describe("protectedBashReadPaths", () => {
  it("returns credential paths consumed by arbitrary Bash commands", async () => {
    await expect(protectedBashReadPaths(`docker run --env-file ${awsCredentials} alpine:latest`, cwd))
      .resolves.toEqual([awsCredentials]);
    await expect(protectedBashReadPaths("cat $HOME/.aws/credentials", cwd)).resolves.toEqual([awsCredentials]);
    await expect(protectedBashReadPaths(`cat ${sshConfig} /etc/hosts`, cwd)).resolves.toEqual([sshConfig]);
    await expect(protectedBashReadPaths(`cat ${certPath} > copy.txt`, cwd)).resolves.toEqual([certPath]);
  });

  it("tracks dotenv paths split across shell quote segments", async () => {
    const command = `cat ${envLocalPath.replace(".env.local", ".en'v.local'")}; gpg --detach-sign artifact`;
    await expect(extractTokensForPathRules(command)).resolves.toEqual([envLocalPath]);
    await expect(protectedBashReadPaths(command, cwd)).resolves.toEqual([envLocalPath]);
  });

  it("tracks credential operands with parentheses", async () => {
    const punctuatedPath = join(homedir(), ".config", "app", "settings(backup).json");
    await expect(protectedBashReadPaths('cat "$HOME/.config/app/settings(backup).json"', cwd))
      .resolves.toEqual([punctuatedPath]);
  });

  it("tracks credential paths embedded with shell HOME parameter expansion", async () => {
    const command = "python3 -c \"print(open('${HOME%/}/.config/app/settings.json').read())\"";
    await expect(protectedBashReadPaths(command, cwd)).resolves.toEqual([appConfig]);
  });

  it("preserves complete parenthetical paths embedded in interpreter source", async () => {
    const punctuatedPath = join(homedir(), ".config", "app", "settings(backup).json");
    const command = `python3 -c "print(open('${punctuatedPath}').read())"`;
    await expect(protectedBashReadPaths(command, cwd)).resolves.toEqual([punctuatedPath]);
  });

  it("tracks credential paths embedded in interpreter source", async () => {
    const command = `python3 -c "print(open('${appConfig}').read())"`;
    await expect(protectedBashReadPaths(command, cwd)).resolves.toEqual([appConfig]);
  });

  it("tracks workspace dotenv operands separately from generic redaction classification", async () => {
    await expect(protectedBashReadPaths(`docker run --env-file ${envPath} alpine:latest`, cwd))
      .resolves.toEqual([envPath]);
    await expect(protectedBashReadPaths(`docker run --env-file ${envLocalPath} alpine:latest`, cwd))
      .resolves.toEqual([envLocalPath]);
    expect(isProtectedCredentialReadPath(envPath, cwd)).toBe(false);
    expect(isProtectedCredentialReadPath(envLocalPath, cwd)).toBe(false);
  });

  it("tracks missing workspace dotenv targets so SRT can deny creation", async () => {
    const missingPath = join(cwd, ".env.new");
    await expect(protectedBashReadPaths(`echo TOKEN=value > ${missingPath}`, cwd))
      .resolves.toEqual([missingPath]);
    await expect(protectedBashReadPaths(`python3 -c "open('${missingPath}', 'w').write('x')"`, cwd))
      .resolves.toEqual([missingPath]);
  });
});

describe("protectedWriteRefusal", () => {
  const masked = [...DEFAULT_MASKED_PATTERNS, join(cwd, "secretdir", "**"), "**/private.cfg"];

  it("accepts a plain single-file target", () => {
    expect(protectedWriteRefusal(join(cwd, "plain.txt"), masked)).toBeUndefined();
  });

  it.each([
    ["whitespace-padded", join(cwd, "plain.txt") + " ", "whitespace"],
    ["glob", join(cwd, "*.txt"), "glob"],
    ["directory", cwd, "regular file"],
    ["default-masked", credentialsJson, "masked"],
    ["custom-masked", join(cwd, "private.cfg"), "masked"],
    ["masked directory root", join(cwd, "secretdir"), "masked"],
    ["mixed-case masked directory", join(cwd, "SecretDir", "x.json"), "masked"],
  ])("refuses a %s target", (_label, target, reason) => {
    expect(protectedWriteRefusal(target, masked)).toContain(reason);
  });
});

describe("prepareApprovedTarget", () => {
  it("creates a missing target as an owner-only empty file", () => {
    const target = join(cwd, "created.txt");
    expect(prepareApprovedTarget(target)).toBeUndefined();
    expect(readFileSync(target, "utf8")).toBe("");
    expect(statSync(target).mode & 0o077).toBe(0);
  });

  it("keeps the content of an existing regular file", () => {
    const target = join(cwd, "existing.txt");
    writeFileSync(target, "keep", "utf8");
    expect(prepareApprovedTarget(target)).toBeUndefined();
    expect(readFileSync(target, "utf8")).toBe("keep");
  });

  it("refuses a symlink target without following it", () => {
    const link = join(cwd, "link.txt");
    symlinkSync(join(cwd, "notes.txt"), link);
    expect(prepareApprovedTarget(link)).toContain("regular file");
  });

  it("refuses a hard-linked target", () => {
    const target = join(cwd, "hard.txt");
    linkSync(join(cwd, "notes.txt"), target);
    expect(prepareApprovedTarget(target)).toContain("hard-linked");
  });

  it("refuses a target under a symlinked directory", () => {
    const dirLink = join(cwd, "dirlink");
    symlinkSync(cwd, dirLink);
    expect(prepareApprovedTarget(join(dirLink, "x.txt"))).toContain("symlinked");
  });

  it("reports a missing parent directory", () => {
    expect(prepareApprovedTarget(join(cwd, "nodir", "x.txt"))).toContain("could not be created");
  });
});
