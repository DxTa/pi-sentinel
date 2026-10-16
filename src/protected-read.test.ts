import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import { afterAll, describe, expect, it } from "vitest";

import { extractTokensForPathRules } from "./handlers/gates/bash-path-extractor";
import { isProtectedCredentialReadPath, protectedBashReadPaths } from "./protected-read";

const cwd = mkdtempSync(join(tmpdir(), "pi-protected-read-workspace-"));
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
