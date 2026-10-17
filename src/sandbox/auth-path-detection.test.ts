import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { detectImplicitAuthAccess } from "./auth-path-detection.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(temporaryPaths.splice(0).map((tempPath) => rm(tempPath, { recursive: true, force: true })));
});

describe("detectImplicitAuthAccess", () => {
  it("discovers SSH keys under the active synthetic home", async () => {
    const home = await mkdtemp(join(tmpdir(), "pi-synthetic-ssh-home-"));
    temporaryPaths.push(home);
    const keyPath = join(home, ".ssh", "id_ed25519");
    await mkdir(join(home, ".ssh"), { recursive: true });
    await writeFile(keyPath, "", { mode: 0o600 });
    vi.stubEnv("HOME", home);
    vi.stubEnv("SSH_AUTH_SOCK", "");

    await expect(detectImplicitAuthAccess("ssh user@example.invalid", null)).resolves.toEqual({
      kind: "ssh-auth",
      candidatePaths: [keyPath],
      needsSocketFallback: false,
      authCommands: ["ssh user@example.invalid"],
    });
  });
  it.each(["git push && echo done", "git -C . push"])(
    "detects SSH auth for Git command form %s",
    async (command) => {
      const home = await mkdtemp(join(tmpdir(), "pi-synthetic-ssh-home-"));
      const repo = await mkdtemp(join(tmpdir(), "pi-synthetic-git-repo-"));
      temporaryPaths.push(home, repo);
      const keyPath = join(home, ".ssh", "id_ed25519");
      await mkdir(join(home, ".ssh"), { recursive: true });
      await mkdir(join(repo, ".git"), { recursive: true });
      await writeFile(keyPath, "", { mode: 0o600 });
      await writeFile(join(repo, ".git", "config"), '[remote "origin"]\nurl = git@example.invalid:repo.git\n');
      vi.stubEnv("HOME", home);
      vi.stubEnv("SSH_AUTH_SOCK", "");

      await expect(detectImplicitAuthAccess(command, repo)).resolves.toEqual({
        kind: "ssh-auth",
        candidatePaths: [keyPath],
        needsSocketFallback: false,
        authCommands: [command === "git push && echo done" ? "git push" : command],
      });
    },
  );

  it.each([
    ["env SSH_AUTH_SOCK=/tmp/agent.sock ssh 'blocked-host'", "ssh blocked-host"],
    ["env -S 'ssh blocked-host'", "env -S ssh blocked-host"],
    ["DOCKER_HOST=unix:///tmp/docker.sock ssh 'blocked-host'", "ssh blocked-host"],
  ])("detects SSH auth through transparent wrappers in %s", async (command, authCommand) => {
    const home = await mkdtemp(join(tmpdir(), "pi-synthetic-ssh-home-"));
    temporaryPaths.push(home);
    const keyPath = join(home, ".ssh", "id_ed25519");
    await mkdir(join(home, ".ssh"), { recursive: true });
    await writeFile(keyPath, "", { mode: 0o600 });
    vi.stubEnv("HOME", home);
    vi.stubEnv("SSH_AUTH_SOCK", "");

    await expect(detectImplicitAuthAccess(command, null)).resolves.toMatchObject({
      kind: "ssh-auth",
      candidatePaths: [keyPath],
      authCommands: [authCommand],
    });
  });

  it("detects SSH hidden inside an unsegmentable command substitution", async () => {
    const home = await mkdtemp(join(tmpdir(), "pi-synthetic-ssh-home-"));
    temporaryPaths.push(home);
    const keyPath = join(home, ".ssh", "id_ed25519");
    await mkdir(join(home, ".ssh"), { recursive: true });
    await writeFile(keyPath, "", { mode: 0o600 });
    vi.stubEnv("HOME", home);
    vi.stubEnv("SSH_AUTH_SOCK", "");

    await expect(detectImplicitAuthAccess('echo "$(ssh blocked-host)"', null)).resolves.toMatchObject({
      kind: "ssh-auth",
      candidatePaths: [keyPath],
      authCommands: ['echo "$(ssh blocked-host)"'],
    });
  });

  it("collects every SSH command for compound-command policy", async () => {
    const home = await mkdtemp(join(tmpdir(), "pi-synthetic-ssh-home-"));
    temporaryPaths.push(home);
    const keyPath = join(home, ".ssh", "id_ed25519");
    await mkdir(join(home, ".ssh"), { recursive: true });
    await writeFile(keyPath, "", { mode: 0o600 });
    vi.stubEnv("HOME", home);
    vi.stubEnv("SSH_AUTH_SOCK", "");

    await expect(detectImplicitAuthAccess("ssh trusted-host && {fd}>out ssh blocked-host", null)).resolves.toMatchObject({
      kind: "ssh-auth",
      candidatePaths: [keyPath],
      authCommands: ["ssh trusted-host", "ssh blocked-host"],
    });
  });

  it("detects synthetic Docker config as implicit auth for direct commands", async () => {
    const home = await mkdtemp(join(tmpdir(), "pi-synthetic-docker-home-"));
    temporaryPaths.push(home);
    const configPath = resolve(home, ".docker/config.json");
    await mkdir(join(home, ".docker"), { recursive: true });
    await writeFile(configPath, "{}\n");
    vi.stubEnv("HOME", home);

    await expect(detectImplicitAuthAccess("docker version", null)).resolves.toEqual({
      kind: "docker-auth",
      candidatePaths: [configPath],
      needsSocketFallback: false,
      authCommands: ["docker version"],
    });
  });

  it("does not infer Docker auth when the synthetic home has no config", async () => {
    const home = await mkdtemp(join(tmpdir(), "pi-synthetic-docker-home-"));
    temporaryPaths.push(home);
    vi.stubEnv("HOME", home);

    await expect(detectImplicitAuthAccess("docker version && cat README.md", null)).resolves.toBeNull();
  });
});
