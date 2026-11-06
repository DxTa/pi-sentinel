import { mkdtemp, readFile, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import { loadThreatFeed, parseHostfile } from "./threat-feed";

// test/setup.ts stubs the loader for every other test.
vi.unmock("./threat-feed");

const HOSTFILE = "# comment\n127.0.0.1\tEvil.Example\n127.0.0.1 other.test # trailing\n\nbad line\n";
const response = (body: string, ok = true) => ({ ok, text: async () => body }) as Response;
const cacheFile = async () => path.join(await mkdtemp(path.join(process.env.TMPDIR ?? tmpdir(), "feed-")), "feed.txt");

describe("parseHostfile", () => {
  it("returns lowercase hosts and skips comments and malformed lines", () => {
    expect([...parseHostfile(HOSTFILE)]).toEqual(["evil.example", "other.test"]);
  });
});

describe("loadThreatFeed", () => {
  it("downloads when there is no cache, then stores it owner-only", async () => {
    const file = await cacheFile();
    const fetchFn = vi.fn(async () => response(HOSTFILE));
    const feed = await loadThreatFeed({ cacheFile: file, fetchFn });

    expect(feed.has("evil.example")).toBe(true);
    expect(await readFile(file, "utf8")).toBe(HOSTFILE);
    expect((await stat(file)).mode & 0o777).toBe(0o600);
  });

  it("uses a fresh cache without downloading", async () => {
    const file = await cacheFile();
    await writeFile(file, HOSTFILE);
    const fetchFn = vi.fn();

    expect((await loadThreatFeed({ cacheFile: file, fetchFn })).has("other.test")).toBe(true);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("falls back to a stale cache when the download fails", async () => {
    const file = await cacheFile();
    await writeFile(file, HOSTFILE);
    const old = new Date(Date.now() - 3 * 24 * 3600 * 1000);
    await utimes(file, old, old);

    const feed = await loadThreatFeed({ cacheFile: file, fetchFn: async () => { throw new Error("offline"); } });
    expect(feed.has("evil.example")).toBe(true);
  });

  it("returns an empty feed when the download fails and there is no cache", async () => {
    const feed = await loadThreatFeed({ cacheFile: await cacheFile(), fetchFn: async () => response("", false) });
    expect(feed.size).toBe(0);
  });
});
