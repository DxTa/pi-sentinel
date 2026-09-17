import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import { isDockerCommand } from "./bypass-command.js";

export type MaskedAuthKind =
  | "ssh-auth"
  | "aws-auth"
  | "kube-auth"
  | "docker-auth"
  | "gpg-auth"
  | "generic-secret";

export interface AuthSensitiveAccessInfo {
  kind: MaskedAuthKind;
  candidatePaths: string[];
  needsSocketFallback: boolean;
}

const SSH_PRIVATE_KEY_CANDIDATES = [
  "id_ed25519",
  "id_rsa",
  "id_ecdsa",
  "id_dsa",
  "id_ed25519_sk",
  "id_ecdsa_sk",
].map((name) => resolve(homedir(), ".ssh", name));

const SSH_AUXILIARY_FILES = [
  resolve(homedir(), ".ssh", "config"),
  resolve(homedir(), ".ssh", "known_hosts"),
];

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => resolve(value)))];
}

export function extractTrailingSimpleCommand(command: string): string {
  const segments = command.split(/(?:&&|\|\||;)/).map((part) => part.trim()).filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1] : command.trim();
}

function commandLooksLikeSsh(command: string): boolean {
  return /^(ssh|scp|sftp)\b/.test(command.trim());
}

function commandLooksLikeAws(command: string): boolean {
  return /^aws\b/.test(command.trim());
}

function commandLooksLikeGpg(command: string): boolean {
  return /^(gpg|gpg-agent|gpgconf|dirmngr)\b/.test(command.trim());
}

function gitConfigBool(repoRoot: string | null, key: string): boolean {
  try {
    const cwd = repoRoot ?? process.cwd();
    const out = execFileSync("git", ["config", "--get", key], { cwd, stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
    return out === "true" || out === "1";
  } catch {
    return false;
  }
}

function commandNeedsGpg(command: string, repoRoot: string | null): boolean {
  const trimmed = command.trim();
  if (commandLooksLikeGpg(trimmed)) return true;
  if (/^git\s+tag\s+.*(-s|--sign)\b/.test(trimmed)) return true;
  if (/^git\s+commit\b/.test(trimmed)) {
    return gitConfigBool(repoRoot, "commit.gpgsign");
  }
  return false;
}

function commandContainsSshUrl(command: string): boolean {
  return /(git@[^\s:]+:|ssh:\/\/)/.test(command);
}

function repoConfigSuggestsSsh(repoRoot: string | null): boolean {
  if (!repoRoot) return false;
  const gitConfig = join(repoRoot, ".git", "config");
  if (!existsSync(gitConfig)) return false;
  try {
    const contents = readFileSync(gitConfig, "utf8");
    return /url\s*=\s*(git@[^\s]+:|ssh:\/\/)/.test(contents);
  } catch {
    return false;
  }
}

function existingPaths(paths: string[]): string[] {
  return paths.filter((path) => existsSync(path));
}

export async function detectImplicitAuthAccess(
  command: string,
  repoRoot: string | null,
): Promise<AuthSensitiveAccessInfo | null> {
  const trimmed = extractTrailingSimpleCommand(command);

  if (commandLooksLikeSsh(trimmed) || commandContainsSshUrl(trimmed)) {
    const privateKeys = existingPaths(SSH_PRIVATE_KEY_CANDIDATES);
    const needsSocketFallback = Boolean(process.env.SSH_AUTH_SOCK) && privateKeys.length === 0;
    if (privateKeys.length === 0) {
      return {
        kind: "ssh-auth",
        candidatePaths: [],
        needsSocketFallback,
      };
    }
    const auxFiles = existingPaths(SSH_AUXILIARY_FILES);
    return {
      kind: "ssh-auth",
      candidatePaths: dedupe([...privateKeys, ...auxFiles]),
      needsSocketFallback: false,
    };
  }

  if (/^git\s+(push|fetch|pull|clone|ls-remote|submodule)\b/.test(trimmed)) {
    if (commandContainsSshUrl(trimmed) || repoConfigSuggestsSsh(repoRoot)) {
      const privateKeys = existingPaths(SSH_PRIVATE_KEY_CANDIDATES);
      const needsSocketFallback = Boolean(process.env.SSH_AUTH_SOCK) && privateKeys.length === 0;
      if (privateKeys.length === 0) {
        return {
          kind: "ssh-auth",
          candidatePaths: [],
          needsSocketFallback,
        };
      }
      const auxFiles = existingPaths(SSH_AUXILIARY_FILES);
      return {
        kind: "ssh-auth",
        candidatePaths: dedupe([...privateKeys, ...auxFiles]),
        needsSocketFallback: false,
      };
    }
  }

  if (isDockerCommand(trimmed)) {
    const configPath = resolve(homedir(), ".docker/config.json");
    if (existsSync(configPath)) {
      return {
        kind: "docker-auth",
        candidatePaths: [configPath],
        needsSocketFallback: false,
      };
    }
  }

  if (commandNeedsGpg(trimmed, repoRoot)) {
    // GPG signing needs gpg-agent socket + pinentry/tty, which the sandbox
    // cannot model safely. Always route to ask-bypass.
    return {
      kind: "gpg-auth",
      candidatePaths: [],
      needsSocketFallback: true,
    };
  }

  if (commandLooksLikeAws(trimmed)) {
    const paths = existingPaths([
      resolve(homedir(), ".aws", "credentials"),
      resolve(homedir(), ".aws", "config"),
    ]);
    if (paths.length > 0) {
      return {
        kind: "aws-auth",
        candidatePaths: dedupe(paths),
        needsSocketFallback: false,
      };
    }
  }

  return null;
}
