import { describe, expect, it } from "vitest";
import { srtEgressFailureMessage } from "./srt-egress-error.js";

describe("srtEgressFailureMessage", () => {
  it("explains a sandbox proxy failure without retrying", () => {
    expect(srtEgressFailureMessage("socat[8] W proxy_connect: connection closed by proxy")).toContain("Sandbox network egress failed");
  });
  it("ignores unrelated errors", () => {
    expect(srtEgressFailureMessage("fatal: permission denied")).toBeUndefined();
  });
});
