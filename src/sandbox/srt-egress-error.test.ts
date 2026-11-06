import { describe, expect, it } from "vitest";
import { srtDenialMessage, srtEgressFailureMessage } from "./srt-egress-error.js";

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

describe("srtDenialMessage", () => {
  it("flags the buildx EPERM denial seen under SRT", () => {
    const output = "open /Users/duc/.docker/buildx/activity/.tmp-default3102642717: operation not permitted";
    expect(srtDenialMessage(output, true)).toContain("call Bash again with the exact original command");
  });
  it("flags read-only and permission denials", () => {
    expect(srtDenialMessage("sh: /x/y: Read-only file system")).toBeDefined();
    expect(srtDenialMessage("cp: cannot create: Permission denied")).toBeDefined();
  });
  it("ignores normal output", () => {
    expect(srtDenialMessage("Successfully built abc123")).toBeUndefined();
  });
});

describe("srtDenialMessage fallback wording", () => {
  it("matches Node error codes", () => {
    expect(srtDenialMessage("Error: EACCES: open '/x'")).toBeDefined();
    expect(srtDenialMessage("Error: EPERM: mkdir '/x'")).toBeDefined();
    expect(srtDenialMessage("Error: EROFS: read-only file system")).toBeDefined();
  });
  it("does not promise a prompt unless host fallback is available", () => {
    const message = srtDenialMessage("Error: EPERM: mkdir '/x'");
    expect(message).toContain("Host fallback is unavailable");
    expect(message).not.toContain("Allow / Deny");
  });
  it("advertises the prompt when host fallback is available", () => {
    const message = srtDenialMessage("Error: EPERM: mkdir '/x'", true);
    expect(message).toContain("Allow / Deny");
    expect(message).toContain("call Bash again with the exact original command");
  });
});
