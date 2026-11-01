import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { helperRuntimePath, nodeRuntimePath } from "./host-runtime.ts";

function withFakeNode(run: (dir: string, fakeNode: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "pi-host-runtime-"));
  const fakeNode = path.join(dir, "node");
  writeFileSync(fakeNode, "");
  try {
    run(dir, fakeNode);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("nodeRuntimePath", () => {
  it.each(["/usr/local/bin/node", "/opt/homebrew/bin/node", "C:\\Program Files\\nodejs\\node.exe"])(
    "keeps a real Node runtime: %s",
    (execPath) => {
      expect(nodeRuntimePath(execPath, "/nowhere")).toBe(execPath);
    },
  );

  it.each(["/Users/me/.pi-bolt/pi-bolt", "/usr/local/bin/pi", "/usr/local/bin/bun"])(
    "uses node from PATH instead of %s, which cannot take Node flags",
    (execPath) => {
      withFakeNode((dir, fakeNode) => {
        expect(nodeRuntimePath(execPath, `/nonexistent${path.delimiter}${dir}`)).toBe(fakeNode);
      });
    },
  );

  it("falls back to bare node when PATH has none", () => {
    expect(nodeRuntimePath("/usr/local/bin/pi", "/nonexistent")).toBe("node");
  });
});

describe("helperRuntimePath", () => {
  it("keeps Bun for plain helper scripts", () => {
    expect(helperRuntimePath("/usr/local/bin/bun", "/nowhere")).toBe("/usr/local/bin/bun");
  });

  it("replaces a compiled pi binary", () => {
    withFakeNode((dir, fakeNode) => {
      expect(helperRuntimePath("/usr/local/bin/pi", dir)).toBe(fakeNode);
    });
  });
});
