/**
 * Threat feed: the URLhaus malware hostfile, cached on disk and refreshed at most once a day.
 * A failed download falls back to the stale cache, then to an empty feed (the other egress checks still apply).
 */

import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

export const THREAT_FEED_URL = "https://urlhaus.abuse.ch/downloads/hostfile/";
const TTL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 15_000;

export interface ThreatFeedOptions {
  cacheFile: string;
  fetchFn?: (url: string, init?: { signal?: AbortSignal }) => Promise<Response>;
  ttlMs?: number;
}

/** Hostfile lines look like "127.0.0.1<tab>host"; comments start with #. */
export function parseHostfile(text: string): Set<string> {
  const hosts = new Set<string>();
  for (const line of text.split("\n")) {
    const fields = line.split("#")[0]!.trim().split(/\s+/);
    if (fields.length === 2 && /^[0-9.:]+$/.test(fields[0]!) && fields[1]) hosts.add(fields[1].toLowerCase());
  }
  return hosts;
}

async function readCache(cacheFile: string): Promise<{ text: string; ageMs: number } | undefined> {
  try {
    const [text, info] = await Promise.all([readFile(cacheFile, "utf8"), stat(cacheFile)]);
    return { text, ageMs: Date.now() - info.mtimeMs };
  } catch {
    return undefined;
  }
}

export async function loadThreatFeed(options: ThreatFeedOptions): Promise<Set<string>> {
  const { cacheFile, fetchFn = fetch, ttlMs = TTL_MS } = options;
  const cached = await readCache(cacheFile);
  if (cached && cached.ageMs < ttlMs) return parseHostfile(cached.text);

  try {
    const response = await fetchFn(THREAT_FEED_URL, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!response.ok) throw new Error(`threat feed HTTP error`);
    const text = await response.text();
    await mkdir(path.dirname(cacheFile), { recursive: true });
    await writeFile(cacheFile, text, { mode: 0o600 });
    return parseHostfile(text);
  } catch {
    return parseHostfile(cached?.text ?? "");
  }
}
