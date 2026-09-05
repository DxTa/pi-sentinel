import { describe, expect, it } from "vitest";

import { resolveAuthExceptionPolicy } from "./auth-exception-policy.js";

describe("resolveAuthExceptionPolicy", () => {
  it("uses explicit matching rule first", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "git push origin main",
      kind: "ssh-auth",
      rules: [{ match: "git push *", kind: "ssh-auth", strategy: "ask-bypass" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });
    expect(resolved.strategy).toBe("ask-bypass");
    expect(resolved.matchedRule?.match).toBe("git push *");
  });

  it("defaults to ask-bypass when socket fallback is needed", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "git push origin main",
      kind: "ssh-auth",
      rules: [],
      hasCandidatePaths: false,
      needsSocketFallback: true,
    });
    expect(resolved.strategy).toBe("ask-bypass");
  });

  it("defaults to ask-unmask when file-based auth paths exist", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "git fetch origin",
      kind: "ssh-auth",
      rules: [],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });
    expect(resolved.strategy).toBe("ask-unmask");
  });

  it("defaults to deny when no auth material exists", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "git fetch origin",
      kind: "ssh-auth",
      rules: [],
      hasCandidatePaths: false,
      needsSocketFallback: false,
    });
    expect(resolved.strategy).toBe("deny");
  });

  it("routes gpg-auth (socket-backed) to ask-bypass regardless of candidate paths", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "git commit -m test",
      kind: "gpg-auth",
      rules: [],
      hasCandidatePaths: false,
      needsSocketFallback: true,
    });
    expect(resolved.strategy).toBe("ask-bypass");
  });
});
