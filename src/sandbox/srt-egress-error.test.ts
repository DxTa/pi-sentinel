import { describe, expect, it } from "vitest";
import { srtEgressFailureMessage } from "./srt-egress-error.js";

describe("srtEgressFailureMessage", () => {
  it("explains a sandbox proxy failure without retrying", () => {
    expect(srtEgressFailureMessage("socat[8] W proxy_connect: connection closed by proxy")).toContain("Sandbox network egress failed");
  });
  it("directs the agent to request approval only when fallback is available", () => {
    const message = srtEgressFailureMessage("socat[8] W proxy_connect: connection closed by proxy", true);
    expect(message).toContain("ONE-TIME HOST FALLBACK IS AVAILABLE");
    expect(message).toContain("call Bash again with the exact original command");
    expect(message).toContain("Allow once / Deny");
  });
  it("does not advertise fallback by default", () => {
    expect(srtEgressFailureMessage("socat[8] W proxy_connect: connection closed by proxy")).toContain("Host fallback is unavailable");
  });
  it("ignores unrelated errors", () => {
    expect(srtEgressFailureMessage("fatal: permission denied")).toBeUndefined();
  });
});
