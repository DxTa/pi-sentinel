import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { detectMaskedFileAccess } from "./masked-file-gate";

const profile = { name: "offline-dev", network: false, roBinds: [], rwBinds: [], env: { allow: [], deny: [] }, maskedPaths: [] };
const dirs: string[] = [];

function workspaceWith(...files: string[]): string {
  const dir = mkdtempSync(path.join(tmpdir(), "pi-masked-gate-"));
  dirs.push(dir);
  for (const file of files) writeFileSync(path.join(dir, file), "x");
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("detectMaskedFileAccess bare relative names", () => {
  it.each([".env", ".env.local", ".env.livecheck", "token.json", "credentials.json", "server.pem"])(
    "flags an existing bare %s",
    (name) => {
      const dir = workspaceWith(name);
      expect(detectMaskedFileAccess(`cat ${name}`, profile, dir)).toEqual([path.join(dir, name)]);
    },
  );

  it("detects both Docker env-file operand spellings", () => {
    const dir = workspaceWith(".env.local");
    const envPath = path.join(dir, ".env.local");
    expect(detectMaskedFileAccess(`docker run --env-file ${envPath} alpine:latest`, profile, dir))
      .toEqual([envPath]);
    expect(detectMaskedFileAccess(`docker run --env-file=${envPath} alpine:latest`, profile, dir))
      .toEqual([envPath]);
    expect(detectMaskedFileAccess(`docker run --env-file=${envPath} alpine:latest`, profile, dir, { includeMissing: true }))
      .toEqual([envPath]);
  });

  it.each([".env.new", ".Env.local"])(
    "finds a dotenv target embedded in interpreter code: %s",
    (name) => {
      const dir = workspaceWith();
      const target = path.join(dir, name);
      const command = `python3 -c "open('${target}', 'w').write('x')"`;
      expect(detectMaskedFileAccess(command, profile, dir, { includeMissing: true })).toContain(target);
    },
  );

  it("ignores ordinary names and missing files", () => {
    const dir = workspaceWith("notes.txt");
    expect(detectMaskedFileAccess("cat notes.txt", profile, dir)).toEqual([]);
    expect(detectMaskedFileAccess("cat .env.missing", profile, dir)).toEqual([]);
  });
});
