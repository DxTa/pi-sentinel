import { link, mkdtemp, rm, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createPiClipboardTempCleanup,
  extractPiClipboardPaths,
  isInsidePiClipboardTempRoot,
  isPiClipboardTempFile,
} from "./clipboard-temp-cleanup.js";

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

  it("trusts only clipboard paths from interactive input", async () => {
    const directory = await makeTempDir();
    const interactivePath = path.join(directory, "pi-clipboard-b46509f4-a820-4442-9013-73da6d2739d2.png");
    const toolInputPath = path.join(directory, "pi-clipboard-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.png");
    await writeFile(interactivePath, "interactive");
    await writeFile(toolInputPath, "tool input");

    const cleanup = createPiClipboardTempCleanup();
    cleanup.trackText(`Tool input ${toolInputPath}`);
    cleanup.trackInteractiveText(`User input ${interactivePath}`);

    expect(cleanup.isTrackedInteractivePath(interactivePath)).toBe(true);
    expect(cleanup.isTrackedInteractivePath(toolInputPath)).toBe(false);
  });
});

describe("isInsidePiClipboardTempRoot", () => {
  it("accepts the per-user macOS temp directory pi writes clipboard files to", () => {
    expect(isInsidePiClipboardTempRoot("/private/var/folders/cg/y8yy1sr16tn788ynxp74hgv80000gn/T/pi-clipboard-uMz5Lh/pi-clipboard-e8779eef-5fc8-4900-8c1f-b2c67b8b0911.png")).toBe(true);
  });

  it("rejects system, device and home paths", () => {
    for (const target of ["/private/etc/hosts", "/private/var/db/x", "/Users/duc/.ssh/id_rsa"]) {
      expect(isInsidePiClipboardTempRoot(target), target).toBe(false);
    }
  });
});

describe("isPiClipboardTempFile hard links", () => {
  it("does not trust a hard link to another file, even under a clipboard name", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "pi-clipboard-link-"));
    tempPaths.push(dir);
    const secret = path.join(dir, "secret.txt");
    const clipboardFile = path.join(dir, `pi-clipboard-${randomUUID()}.png`);
    await writeFile(secret, "secret", "utf8");
    await link(secret, clipboardFile);

    expect(isPiClipboardTempFile(clipboardFile)).toBe(false);
  });
});
