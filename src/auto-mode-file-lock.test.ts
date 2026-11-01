import { describe, expect, it } from "vitest";

import { lockCommand } from "./auto-mode-file-lock.js";

describe("lockCommand", () => {
  it("uses an absolute flock executable on Linux", () => {
    expect(lockCommand("/tmp/pi-sentinel.lock", "linux").command).toBe("/usr/bin/flock");
  });
});

describe("lockCommand runtime", () => {
  it("runs the lock holder with the given runtime, not the host binary", () => {
    const { args } = lockCommand("/tmp/pi-sentinel.lock", "linux", "/usr/bin/node");
    expect(args.slice(0, 4)).toEqual(["-x", "/tmp/pi-sentinel.lock", "/usr/bin/node", "-e"]);
  });
});
