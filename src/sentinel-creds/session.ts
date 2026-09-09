/**
 * Persistent read-whitelist and session state for sentinel-creds.
 */
import {
  existsSync, readFileSync, writeFileSync, statSync, mkdirSync,
} from "node:fs";
import { resolve, basename, dirname, join } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";

import type { SentinelCredsConfig } from "./config";
import type { ScanResult } from "./scanner";
import { MAX_SCAN_BYTES } from "./scanner";

// ── Whitelist types ──────────────────────────────────────────────────────

interface WhitelistEntry {
  path: string;
  sha256?: string;
  mtimeMs?: number;
  addedAt?: string;
  expiresAt?: string;
  reason?: string;
}

// ── Whitelist helpers ────────────────────────────────────────────────────

function getAgentDir(): string {
  const envDir = process.env.PI_CODING_AGENT_DIR;
  if (!envDir) return join(homedir(), ".pi", "agent");
  if (envDir === "~") return homedir();
  if (envDir.startsWith("~/")) return join(homedir(), envDir.slice(2));
  return envDir;
}

function projectScopeId(cwd: string): string {
  const normalized = resolve(cwd);
  const slug = (basename(normalized) || "root")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || "root";
  const hash = createHash("sha256").update(normalized).digest("hex").slice(0, 12);
  return `${slug}-${hash}`;
}

function getWhitelistDir(): string {
  return join(getAgentDir(), "sentinel-creds-whitelist");
}

function getWhitelistPath(cwd: string): string {
  return join(getWhitelistDir(), `${projectScopeId(cwd)}.json`);
}

export function hashFile(absolutePath: string): { sha256: string; mtimeMs: number } | undefined {
  try {
    const fileStat = statSync(absolutePath);
    if (!fileStat.isFile() || fileStat.size > MAX_SCAN_BYTES) return undefined;
    const content = readFileSync(absolutePath);
    return {
      sha256: createHash("sha256").update(content).digest("hex"),
      mtimeMs: fileStat.mtimeMs,
    };
  } catch {
    return undefined;
  }
}

function isWhitelistEntryValid(entry: WhitelistEntry): boolean {
  if (entry.expiresAt && Date.now() > Date.parse(entry.expiresAt)) return false;
  if (!entry.sha256) return true; // backwards-compatible legacy entry
  const current = hashFile(entry.path);
  return !!current && current.sha256 === entry.sha256 && current.mtimeMs === entry.mtimeMs;
}

function loadReadWhitelist(cwd: string): Map<string, WhitelistEntry> {
  const filePath = getWhitelistPath(cwd);
  const entries = new Map<string, WhitelistEntry>();
  try {
    if (existsSync(filePath)) {
      const raw = JSON.parse(readFileSync(filePath, "utf-8")) as { readPaths?: string[]; entries?: WhitelistEntry[] };
      for (const path of Array.isArray(raw.readPaths) ? raw.readPaths : []) {
        entries.set(path, { path });
      }
      for (const entry of Array.isArray(raw.entries) ? raw.entries : []) {
        if (entry.path) entries.set(entry.path, entry);
      }
    }
  } catch { /* empty */ }
  for (const [path, entry] of entries) {
    if (!isWhitelistEntryValid(entry)) entries.delete(path);
  }
  return entries;
}

function saveReadWhitelist(cwd: string, entries: Map<string, WhitelistEntry>): void {
  const filePath = getWhitelistPath(cwd);
  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify({ entries: [...entries.values()] }, null, 2) + "\n", "utf-8");
  } catch { /* silently fail */ }
}

// ── CredsSession class ───────────────────────────────────────────────────

export class CredsSession {
  private scanCache = new Map<string, { mtimeMs: number; result: ScanResult }>();
  private readWhitelist: Map<string, WhitelistEntry>;
  private cwd: string;
  private config: SentinelCredsConfig;
  /** Read results explicitly allowed for a specific tool call. */
  private allowedReadResults = new Map<string, string>();
  /** Bash results explicitly allowed for a specific tool call. */
  private allowedBashResults = new Map<string, string>();

  constructor(cwd: string, config: SentinelCredsConfig) {
    this.cwd = cwd;
    this.config = config;
    this.readWhitelist = loadReadWhitelist(cwd);
  }

  reset(config: SentinelCredsConfig, cwd = this.cwd): void {
    this.scanCache.clear();
    this.cwd = cwd;
    this.config = config;
    this.readWhitelist = loadReadWhitelist(this.cwd);
    this.allowedReadResults.clear();
    this.allowedBashResults.clear();
  }

  getCachedScan(absolutePath: string, currentMtimeMs: number): ScanResult | undefined {
    const cached = this.scanCache.get(absolutePath);
    if (!cached) return undefined;
    if (cached.mtimeMs !== currentMtimeMs) {
      this.scanCache.delete(absolutePath);
      return undefined;
    }
    return cached.result;
  }

  cacheScan(absolutePath: string, mtimeMs: number, result: ScanResult): void {
    this.scanCache.set(absolutePath, { mtimeMs, result });
  }

  invalidateScanCache(absolutePath: string): void {
    this.scanCache.delete(absolutePath);
  }

  isReadWhitelisted(absolutePath: string): boolean {
    const entry = this.readWhitelist.get(absolutePath);
    if (entry && isWhitelistEntryValid(entry)) return true;
    if (entry) {
      this.readWhitelist.delete(absolutePath);
      saveReadWhitelist(this.cwd, this.readWhitelist);
    }
    return this.config.readAllowedPaths.includes(absolutePath);
  }

  resolvePath(rawPath: string): string {
    return resolve(this.cwd, rawPath.startsWith("@") ? rawPath.slice(1) : rawPath);
  }

  addToReadWhitelist(absolutePath: string, reason = "user allowed file"): void {
    const fingerprint = hashFile(absolutePath);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.config.whitelistTtlHours * 60 * 60 * 1000);
    this.readWhitelist.set(absolutePath, {
      path: absolutePath,
      sha256: fingerprint?.sha256,
      mtimeMs: fingerprint?.mtimeMs,
      addedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      reason,
    });
    saveReadWhitelist(this.cwd, this.readWhitelist);
  }

  allowReadResult(toolCallId: string, absolutePath: string): void {
    this.allowedReadResults.set(toolCallId, absolutePath);
  }

  isReadResultAllowed(toolCallId: string, absolutePath: string): boolean {
    return this.allowedReadResults.get(toolCallId) === absolutePath || this.isReadWhitelisted(absolutePath);
  }

  allowBashResult(toolCallId: string, command: string): void {
    this.allowedBashResults.set(toolCallId, command);
  }

  isBashResultAllowed(toolCallId: string, command: string): boolean {
    return this.allowedBashResults.get(toolCallId) === command;
  }

  consumeReadResultAllowance(toolCallId: string, absolutePath: string): boolean {
    if (!this.isReadResultAllowed(toolCallId, absolutePath)) return false;
    this.allowedReadResults.delete(toolCallId);
    return true;
  }

  consumeBashResultAllowance(toolCallId: string, command: string): boolean {
    if (!this.isBashResultAllowed(toolCallId, command)) return false;
    this.allowedBashResults.delete(toolCallId);
    return true;
  }
}
