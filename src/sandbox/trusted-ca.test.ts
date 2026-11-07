import { mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { trustedCaFile } from "./trusted-ca.js";

describe("trusted CA path", () => {
  it("permits a PEM certificate path but keeps other masks and canonical paths protected", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "pi-trusted-ca-"));
    try {
      const pem = path.join(dir, "ca.pem");
      const secret = path.join(dir, "secrets.json");
      const alias = path.join(dir, "alias.pem");
      writeFileSync(pem, "test");
      writeFileSync(secret, "test");
      symlinkSync(secret, alias);
      expect(trustedCaFile(pem, [])).toEqual({ value: pem, path: realpathSync(pem) });
      expect(trustedCaFile(pem, [`${dir}/**`])).toBeUndefined();
      expect(trustedCaFile(secret, [])).toBeUndefined();
      expect(trustedCaFile(alias, [])).toBeUndefined();
      expect(trustedCaFile("relative.pem", [])).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
