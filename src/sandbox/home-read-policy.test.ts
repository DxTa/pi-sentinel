import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import { wrapCommandWithSandboxMacOS } from "@anthropic-ai/sandbox-runtime/dist/sandbox/macos-sandbox-utils.js";
import { buildSrtCommandSpec } from "./srt-command-spec.js";
import { buildSrtRuntimeConfig } from "./srt-runtime-config.js";
import { resolveHomeReadPolicy } from "./home-read-policy.js";

const directories: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function directory(prefix: string): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  directories.push(dir);
  return dir;
}

describe("yolo home sandbox protection", () => {
  it("only enables home visibility in yolo on macOS and fails closed on unsupported deny patterns", () => {
    const envRules = [{ surface: "path", pattern: "*.env", action: "deny" as const }];
    expect(resolveHomeReadPolicy("yolo", envRules, "darwin").enabled).toBe(true);
    expect(resolveHomeReadPolicy("yolo", envRules, "linux").enabled).toBe(false);
    expect(resolveHomeReadPolicy("auto", envRules, "darwin").enabled).toBe(false);
    expect(resolveHomeReadPolicy("yolo", [{ surface: "path", pattern: "*secret*", action: "deny" }], "darwin").enabled).toBe(false);
    expect(resolveHomeReadPolicy("yolo", [{ surface: "read", pattern: "~/finance/*", action: "deny" }], "darwin").enabled).toBe(false);
  });

  it.skipIf(process.platform !== "darwin")("enforces explicit path denies inside the sandbox", async () => {
    const home = await directory("pi-home-policy-deny-");
    const workspace = await directory("pi-home-policy-work-");
    const privatePath = join(home, "private-secret!");
    await writeFile(privatePath, "SECRET");
    vi.stubEnv("HOME", home);
    const policy = resolveHomeReadPolicy("yolo", [
      { surface: "read", pattern: privatePath, action: "deny" },
      { surface: "path", pattern: "*.env", action: "deny" },
    ]);
    expect(policy.enabled).toBe(true);
    const spec = buildSrtCommandSpec({
      homeReadOnly: policy.enabled, homeDenyPaths: policy.denyPaths,
      command: "echo ok", cwd: workspace, repoRoot: workspace,
      sandboxConfig: { enabled: true, profiles: {}, defaultProfile: "online-dev" },
      profile: { name: "online-dev", network: true, maskedPaths: [], env: { allow: [], deny: [] } },
    });
    const fs = buildSrtRuntimeConfig(spec).filesystem;
    const result = spawnSync("/bin/sh", ["-c", wrapCommandWithSandboxMacOS({
      command: `/bin/cat '${privatePath}'`, needsNetworkRestriction: false,
      readConfig: { denyOnly: fs.denyRead, allowWithinDeny: fs.allowRead },
      writeConfig: { allowOnly: fs.allowWrite, denyWithinAllow: fs.denyWrite },
    })], { encoding: "utf8", cwd: workspace });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
    const uppercase = join(home, "PRIVATE-SECRET!");
    if (existsSync(uppercase)) {
      const alternate = spawnSync("/bin/sh", ["-c", wrapCommandWithSandboxMacOS({
        command: `/bin/cat '${uppercase}'`, needsNetworkRestriction: false,
        readConfig: { denyOnly: fs.denyRead, allowWithinDeny: fs.allowRead },
        writeConfig: { allowOnly: fs.allowWrite, denyWithinAllow: fs.denyWrite },
      })], { encoding: "utf8", cwd: workspace });
      expect(alternate.status).not.toBe(0);
    }
    const later = join(home, "app.env");
    await writeFile(later, "SECRET");
    const laterResult = spawnSync("/bin/sh", ["-c", wrapCommandWithSandboxMacOS({
      command: `/bin/cat '${later}'`, needsNetworkRestriction: false,
      readConfig: { denyOnly: fs.denyRead, allowWithinDeny: fs.allowRead },
      writeConfig: { allowOnly: fs.allowWrite, denyWithinAllow: fs.denyWrite },
    })], { encoding: "utf8", cwd: workspace });
    expect(laterResult.status).not.toBe(0);
  });

  it.skipIf(process.platform !== "darwin")("keeps cloud workspaces usable without exposing other Library files", async () => {
    const home = await directory("pi-home-cloud-");
    const workspace = join(home, "Library", "CloudStorage", "Drive", "project");
    await mkdir(workspace, { recursive: true });
    await writeFile(join(home, "Library", "private"), "SECRET");
    vi.stubEnv("HOME", home);
    const spec = buildSrtCommandSpec({
      homeReadOnly: true, command: "echo ok", cwd: workspace, repoRoot: workspace,
      sandboxConfig: { enabled: true, profiles: {}, defaultProfile: "online-dev" },
      profile: { name: "online-dev", network: true, maskedPaths: [], env: { allow: [], deny: [] } },
    });
    const fs = buildSrtRuntimeConfig(spec).filesystem;
    const run = (command: string) => spawnSync("/bin/sh", ["-c", wrapCommandWithSandboxMacOS({
      command, needsNetworkRestriction: false,
      readConfig: { denyOnly: fs.denyRead, allowWithinDeny: fs.allowRead },
      writeConfig: { allowOnly: fs.allowWrite, denyWithinAllow: fs.denyWrite },
    })], { encoding: "utf8", cwd: workspace });
    expect(run(`/bin/echo OK > '${join(workspace, "test.txt")}'`).status).toBe(0);
    expect(run(`/bin/cat '${join(workspace, "test.txt")}'`).stdout.trim()).toBe("OK");
    expect(run(`/bin/cat '${join(home, "Library", "private")}'`).status).not.toBe(0);
    expect(run(`/bin/echo BAD > '${join(home, "Library", "private")}'`).status).not.toBe(0);
  });

  it.skipIf(process.platform !== "darwin")("allows home reads but denies existing and newly created secrets, aliases and writes in real macOS SRT", async () => {
    const home = await directory("pi-home-read-live-");
    const workspace = await directory("pi-home-read-workspace-");
    const credentials = await directory("pi-home-read-credentials-");
    vi.stubEnv("HOME", home);
    await writeFile(join(home, "notes.txt"), "ordinary home content");
    await symlink(credentials, join(home, ".ssh"));
    await mkdir(join(home, "Library"));
    await writeFile(join(home, "Library", "secret"), "SYNTHETIC");
    await mkdir(join(home, ".azure"));
    await writeFile(join(home, ".azure", "token"), "SYNTHETIC");
    await writeFile(join(home, ".vault-token"), "SYNTHETIC");
    const spec = buildSrtCommandSpec({
      homeReadOnly: true, command: "echo ok", cwd: workspace, repoRoot: workspace,
      sandboxConfig: { enabled: true, profiles: {}, defaultProfile: "online-dev", roBinds: [], rwBinds: [] },
      profile: { name: "online-dev", network: true, roBinds: [], rwBinds: [], maskedPaths: ["**/*.private"] },
    });
    const fs = buildSrtRuntimeConfig(spec).filesystem;
    // Create protected files after preparation: macOS must enforce masks at read time.
    await writeFile(join(home, "late.key"), "synthetic private key");
    await writeFile(join(home, "late.private"), "synthetic configured secret");
    await writeFile(join(home, ".npmrc"), "synthetic registry token");
    await mkdir(join(home, ".claude", "projects"), { recursive: true });
    await writeFile(join(home, ".claude", "projects", "transcript"), "synthetic transcript");
    await writeFile(join(credentials, "id_ed25519"), "synthetic ssh key");
    await symlink(join(credentials, "id_ed25519"), join(home, "public-alias"));
    await mkdir(join(home, "nested"));
    await writeFile(join(home, "nested", "secret.pem"), "synthetic pem");
    const run = (command: string) => spawnSync("/bin/sh", ["-c", wrapCommandWithSandboxMacOS({
      command, needsNetworkRestriction: false,
      readConfig: { denyOnly: fs.denyRead, allowWithinDeny: fs.allowRead },
      writeConfig: { allowOnly: fs.allowWrite, denyWithinAllow: fs.denyWrite },
    })], { encoding: "utf8", cwd: workspace });
    const read = run(`/bin/cat '${join(home, "notes.txt")}'`);
    expect(read.status, read.stderr).toBe(0);
    expect(read.stdout).toBe("ordinary home content");
    for (const file of ["late.key", "late.private", ".npmrc", "public-alias", "nested/secret.pem", ".ssh/id_ed25519", "Library/secret", ".azure/token", ".vault-token", ".claude/projects/transcript"]) {
      const result = run(`/bin/cat '${join(home, file)}'`);
      expect(result.status, `${file}: ${result.stdout} ${result.stderr}`).not.toBe(0);
      expect(result.stdout).toBe("");
    }
    const write = run(`/bin/echo changed > '${join(home, "notes.txt")}'`);
    expect(write.status, write.stderr).not.toBe(0);
    expect(run(`/bin/cat '${join(home, "notes.txt")}'`).stdout).toBe("ordinary home content");
  });

  it.skipIf(process.platform !== "darwin")("keeps approved workspace dotenv files readable", async () => {
    const home = await directory("pi-home-read-dotenv-");
    const workspace = join(home, "workspace");
    await mkdir(workspace);
    const dotenv = join(workspace, ".env");
    await writeFile(dotenv, "SYNTHETIC_TEST_ONLY");
    vi.stubEnv("HOME", home);
    const spec = buildSrtCommandSpec({
      homeReadOnly: true, command: "echo ok", cwd: workspace, repoRoot: workspace,
      sandboxConfig: { enabled: true, profiles: {}, defaultProfile: "online-dev" },
      profile: { name: "online-dev", network: true, maskedPaths: [], env: { allow: [], deny: [] } },
      unmaskedPaths: [{ path: dotenv, writable: false }],
    });
    const fs = buildSrtRuntimeConfig(spec).filesystem;
    const result = spawnSync("/bin/sh", ["-c", wrapCommandWithSandboxMacOS({
      command: `/bin/cat '${dotenv}'`, needsNetworkRestriction: false,
      readConfig: { denyOnly: fs.denyRead, allowWithinDeny: fs.allowRead },
      writeConfig: { allowOnly: fs.allowWrite, denyWithinAllow: fs.denyWrite },
    })], { encoding: "utf8", cwd: workspace });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("SYNTHETIC_TEST_ONLY");
    const other = join(workspace, ".env.other");
    await writeFile(other, "NOT_APPROVED");
    const denied = spawnSync("/bin/sh", ["-c", wrapCommandWithSandboxMacOS({
      command: `/bin/cat '${other}'`, needsNetworkRestriction: false,
      readConfig: { denyOnly: fs.denyRead, allowWithinDeny: fs.allowRead },
      writeConfig: { allowOnly: fs.allowWrite, denyWithinAllow: fs.denyWrite },
    })], { encoding: "utf8", cwd: workspace });
    expect(denied.status, denied.stderr).not.toBe(0);
  });
});
