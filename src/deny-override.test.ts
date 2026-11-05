import { homedir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canAutoGrantOverride, markDenyOverride, takeDenyOverride } from "./deny-override";

describe("deny override", () => {
  it("is taken exactly once per tool call", () => {
    markDenyOverride("call-1");
    expect(takeDenyOverride("call-1")).toBe(true);
    expect(takeDenyOverride("call-1")).toBe(false);
    expect(takeDenyOverride(undefined)).toBe(false);
  });

  it("auto-grants ordinary external paths", () => {
    expect(canAutoGrantOverride(["/opt/shared/notes.txt"], "/work/project")).toBe(true);
  });

  it.each(["/etc", "/usr/bin", join(homedir(), ".ssh"), join(homedir(), ".aws", "credentials")])(
    "keeps the separate sandbox prompt for %s",
    (path) => {
      expect(canAutoGrantOverride(["/opt/shared/notes.txt", path], "/work/project")).toBe(false);
    },
  );
});
