import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createPiClipboardTempCleanup, extractPiClipboardPaths } from "./clipboard-temp-cleanup.js";

const tempPaths: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "pi-clipboard-test-"));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("extractPiClipboardPaths", () => {
  it("extracts generated clipboard image paths from user text", () => {
    expect(extractPiClipboardPaths(
      "Inspect /var/folders/cg/T/pi-clipboard-b46509f4-a820-4442-9013-73da6d2739d2.png.",
    )).toEqual([
      "/var/folders/cg/T/pi-clipboard-b46509f4-a820-4442-9013-73da6d2739d2.png",
    ]);
  });

  it("ignores non-clipboard paths", () => {
    expect(extractPiClipboardPaths("/tmp/image.png /tmp/pi-clipboard-not-a-uuid.png")).toEqual([]);
  });
});

describe("createPiClipboardTempCleanup", () => {
  it("removes tracked clipboard files and leaves untracked files alone", async () => {
    const directory = await makeTempDir();
    const tracked = path.join(directory, "pi-clipboard-b46509f4-a820-4442-9013-73da6d2739d2.png");
    const untracked = path.join(directory, "pi-clipboard-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.png");
    await writeFile(tracked, "tracked");
    await writeFile(untracked, "untracked");

    const cleanup = createPiClipboardTempCleanup();
    cleanup.trackText(`Inspect ${tracked}`);
    cleanup.cleanup();

    await expect(rm(tracked)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(rm(untracked)).resolves.toBeUndefined();
  });
});
