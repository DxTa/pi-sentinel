import { describe, expect, it } from "vitest";

import { lockCommand } from "./auto-mode-file-lock.js";

describe("lockCommand", () => {
  it("uses an absolute flock executable on Linux", () => {
    expect(lockCommand("/tmp/pi-sentinel.lock", "linux").command).toBe("/usr/bin/flock");
  });
});
