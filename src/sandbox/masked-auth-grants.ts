import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

import type { MaskedAuthKind } from "./auth-path-detection.js";

interface MaskedAuthGrantStore {
  projects: Record<string, Partial<Record<MaskedAuthKind, string[]>>>;
}

const sessionMaskedAuthGrants = new Map<string, Map<MaskedAuthKind, Set<string>>>();

function grantsPath(): string {
  return join(homedir(), ".pi", "agent", "extensions", "pi-sentinel", "masked-auth-grants.json");
}

function normalizeStore(data: unknown): MaskedAuthGrantStore {
  if (!data || typeof data !== "object") return { projects: {} };
  const projects = (data as { projects?: Record<string, Partial<Record<MaskedAuthKind, string[]>>> }).projects ?? {};
  return { projects };
}

function loadStore(): MaskedAuthGrantStore {
  const path = grantsPath();
  if (!existsSync(path)) return { projects: {} };
  try {
    return normalizeStore(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return { projects: {} };
  }
}

function saveStore(store: MaskedAuthGrantStore): void {
  const path = grantsPath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(store, null, 2)}\n`, "utf8");
}

function normalizeRepoRoot(repoRoot: string): string {
  return resolve(repoRoot);
}

function normalizePath(targetPath: string): string {
  return resolve(targetPath);
}

function canonicalizePath(targetPath: string): string {
  const normalized = normalizePath(targetPath);
  try {
    return realpathSync.native(normalized);
  } catch {
    return normalized;
  }
}

export function getMaskedAuthSessionGrants(repoRoot: string, kind: MaskedAuthKind): string[] {
  const repo = normalizeRepoRoot(repoRoot);
  return [...(sessionMaskedAuthGrants.get(repo)?.get(kind) ?? new Set<string>())].map(normalizePath);
}

export function clearMaskedAuthSessionGrants(): void {
  sessionMaskedAuthGrants.clear();
}

export function addMaskedAuthSessionGrant(repoRoot: string, kind: MaskedAuthKind, targetPath: string): void {
  const repo = normalizeRepoRoot(repoRoot);
  const normalized = canonicalizePath(targetPath);
  let byKind = sessionMaskedAuthGrants.get(repo);
  if (!byKind) {
    byKind = new Map();
    sessionMaskedAuthGrants.set(repo, byKind);
  }
  let set = byKind.get(kind);
  if (!set) {
    set = new Set();
    byKind.set(kind, set);
  }
  set.add(normalized);
}

export function getMaskedAuthPersistentGrants(repoRoot: string, kind: MaskedAuthKind): string[] {
  const store = loadStore();
  const repo = normalizeRepoRoot(repoRoot);
  return (store.projects[repo]?.[kind] ?? []).map(normalizePath);
}

export function addMaskedAuthPersistentGrant(repoRoot: string, kind: MaskedAuthKind, targetPath: string): void {
  const store = loadStore();
  const repo = normalizeRepoRoot(repoRoot);
  const normalized = canonicalizePath(targetPath);
  const repoEntry = store.projects[repo] ?? {};
  const values = new Set((repoEntry[kind] ?? []).map(normalizePath));
  values.add(normalized);
  repoEntry[kind] = [...values];
  store.projects[repo] = repoEntry;
  saveStore(store);
}
