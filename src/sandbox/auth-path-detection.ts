import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import { bashInnerCommands, bashLiteralWords, bashWordsWithoutRedirections, splitBashSegments } from "../bash-segments.js";
import { isDockerDaemonCommand } from "./bypass-command.js";

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
  authCommands: string[];
}

const SSH_PRIVATE_KEY_NAMES = [
  "id_ed25519",
  "id_rsa",
  "id_ecdsa",
  "id_dsa",
  "id_ed25519_sk",
  "id_ecdsa_sk",
];

function sshAuthCandidatePaths(): { privateKeys: string[]; auxiliaryFiles: string[] } {
  const sshDir = resolve(homedir(), ".ssh");
  return {
    privateKeys: SSH_PRIVATE_KEY_NAMES.map((name) => resolve(sshDir, name)),
    auxiliaryFiles: [resolve(sshDir, "config"), resolve(sshDir, "known_hosts")],
  };
}

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

type AuthAccessEvidence = Omit<AuthSensitiveAccessInfo, "authCommands">;

function sshAuthEvidence(): AuthAccessEvidence {
  const sshPaths = sshAuthCandidatePaths();
  const privateKeys = existingPaths(sshPaths.privateKeys);
  const needsSocketFallback = Boolean(process.env.SSH_AUTH_SOCK) && privateKeys.length === 0;
  const auxiliaryFiles = privateKeys.length > 0 ? existingPaths(sshPaths.auxiliaryFiles) : [];
  return {
    kind: "ssh-auth",
    candidatePaths: [...privateKeys, ...auxiliaryFiles],
    needsSocketFallback,
  };
}

function detectSshAuth(
  command: string,
  repoRoot: string | null,
  opaque: boolean,
): AuthAccessEvidence | null {
  const gitSshCommand = /^git\s+(?:-C\s+(?:"[^"]*"|'[^']*'|\S+)\s+)*(push|fetch|pull|clone|ls-remote|submodule)\b/.test(command)
    && (commandContainsSshUrl(command) || repoConfigSuggestsSsh(repoRoot));
  const opaqueSshCommand = opaque && /\b(?:ssh|scp|sftp)\b/.test(command);
  if (!commandLooksLikeSsh(command) && !commandContainsSshUrl(command) && !gitSshCommand && !opaqueSshCommand) {
    return null;
  }
  return sshAuthEvidence();
}

function detectDockerAuth(command: string): AuthAccessEvidence | null {
  if (!isDockerDaemonCommand(command)) return null;
  const configPath = resolve(homedir(), ".docker/config.json");
  return existsSync(configPath)
    ? { kind: "docker-auth", candidatePaths: [configPath], needsSocketFallback: false }
    : null;
}

function detectGpgAuth(command: string, repoRoot: string | null, opaque: boolean): AuthAccessEvidence | null {
  const opaqueGpgCommand = opaque && /\b(?:gpg|gpg-agent|gpgconf|dirmngr)\b/.test(command);
  if (!commandNeedsGpg(command, repoRoot) && !opaqueGpgCommand) return null;
  // GPG signing needs gpg-agent socket + pinentry/tty, which the sandbox cannot model safely.
  return { kind: "gpg-auth", candidatePaths: [], needsSocketFallback: true };
}

function detectAwsAuth(command: string, opaque: boolean): AuthAccessEvidence | null {
  if (!commandLooksLikeAws(command) && !(opaque && /\baws\b/.test(command))) return null;
  const candidatePaths = existingPaths([
    resolve(homedir(), ".aws", "credentials"),
    resolve(homedir(), ".aws", "config"),
  ]);
  return candidatePaths.length > 0
    ? { kind: "aws-auth", candidatePaths, needsSocketFallback: false }
    : null;
}

function detectAuthEvidence(command: string, repoRoot: string | null, opaque: boolean): AuthAccessEvidence[] {
  const ssh = detectSshAuth(command, repoRoot, opaque);
  if (ssh) return [ssh];

  return [
    detectDockerAuth(command),
    detectGpgAuth(command, repoRoot, opaque),
    detectAwsAuth(command, opaque),
  ].filter((evidence): evidence is AuthAccessEvidence => evidence !== null);
}

function mergeAuthEvidence(
  detected: AuthSensitiveAccessInfo | null,
  next: AuthAccessEvidence,
  authCommand: string,
): AuthSensitiveAccessInfo {
  if (!detected) return { ...next, candidatePaths: dedupe(next.candidatePaths), authCommands: [authCommand] };
  if (detected.kind !== next.kind) {
    return {
      kind: "generic-secret",
      candidatePaths: [],
      needsSocketFallback: false,
      authCommands: [...detected.authCommands, authCommand],
    };
  }
  return {
    ...detected,
    candidatePaths: dedupe([...detected.candidatePaths, ...next.candidatePaths]),
    needsSocketFallback: detected.needsSocketFallback || next.needsSocketFallback,
    authCommands: detected.authCommands.includes(authCommand)
      ? detected.authCommands
      : [...detected.authCommands, authCommand],
  };
}

export async function detectImplicitAuthAccess(
  command: string,
  repoRoot: string | null,
): Promise<AuthSensitiveAccessInfo | null> {
  const parsedCommands = bashInnerCommands(command);
  const simpleCommands = parsedCommands?.commands ?? [command.trim()].filter(Boolean);
  let detected: AuthSensitiveAccessInfo | null = null;

  for (const segment of simpleCommands) {
    const opaque = parsedCommands === null || parsedCommands.opaque;
    const opaqueSshHereString = opaque
      && /\b(?:bash|sh|zsh|dash)\b[^\n]*<<<[^\n]*\b(?:ssh|scp|sftp)\b/.test(segment);
    const trimmed = opaqueSshHereString
      ? segment.trim()
      : bashLiteralWords(segment)?.join(" ")
        ?? bashWordsWithoutRedirections(segment)?.join(" ")
        ?? segment.trim();
    for (const evidence of detectAuthEvidence(trimmed, repoRoot, opaque)) {
      detected = mergeAuthEvidence(detected, evidence, trimmed);
    }
  }

  return detected;
}
