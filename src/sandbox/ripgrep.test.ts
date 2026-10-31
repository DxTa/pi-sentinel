import { accessSync, constants } from "node:fs";

import { describe, expect, it } from "vitest";

import { bundledRipgrepPath, ripgrepCommand } from "./ripgrep.js";

describe("bundled ripgrep", () => {
  it("resolves an executable from @vscode/ripgrep on supported platforms", () => {
    const rgPath = bundledRipgrepPath();
    expect(rgPath).not.toBeNull();
    expect(() => accessSync(String(rgPath), constants.X_OK)).not.toThrow();
    expect(ripgrepCommand()).toBe(rgPath);
  });
});
