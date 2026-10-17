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

  it("gives any matching deny rule precedence over an earlier bypass rule", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "ssh blocked-host",
      kind: "ssh-auth",
      rules: [
        { match: "ssh *", kind: "ssh-auth", strategy: "ask-bypass" },
        { match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" },
      ],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
    expect(resolved.matchedRule?.match).toBe("ssh blocked-host*");
  });

  it("applies auth deny rules to the detected command inside a chain", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "git push origin main && echo done",
      authCommands: ["git push origin main"],
      kind: "ssh-auth",
      rules: [{ match: "git push *", kind: "ssh-auth", strategy: "deny" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
    expect(resolved.matchedRule?.match).toBe("git push *");
  });

  it("matches explicit SSH denies across adjacent quoted fragments", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "ssh 'block'ed-host",
      kind: "ssh-auth",
      rules: [{ match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
    expect(resolved.matchedRule?.match).toBe("ssh blocked-host*");
  });

  it("fails closed when env split-string hides an SSH target from explicit deny matching", () => {
    const command = "env -S 'ssh blocked-host'";
    const resolved = resolveAuthExceptionPolicy({
      command,
      authCommands: [command],
      kind: "ssh-auth",
      rules: [{ match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
    expect(resolved.reason).toContain("SSH target could not be normalized");
  });

  it("fails closed when an explicit SSH deny cannot normalize a dynamic target", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: 'ssh "$HOST"',
      kind: "ssh-auth",
      rules: [{ match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
  });

  it("keeps a later auth deny rule visible after descriptor redirection", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "ssh trusted-host && {fd}>out ssh blocked-host",
      authCommands: ["ssh trusted-host", "ssh blocked-host"],
      kind: "ssh-auth",
      rules: [{ match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
  });

  it("denies mixed auth mechanisms even when another candidate path exists", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "ssh trusted-host && ssh blocked-host; gpg --version; cat .env",
      authCommands: ["ssh trusted-host", "ssh blocked-host", "gpg --version"],
      kind: "generic-secret",
      rules: [{ match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
  });

  it("denies auth commands when shell splitting failed", () => {
    const command = 'ssh trusted-host && ssh blocked-host "$(printf x)"';
    const resolved = resolveAuthExceptionPolicy({
      command,
      authCommands: [command],
      kind: "ssh-auth",
      rules: [
        { match: "ssh trusted-host*", kind: "ssh-auth", strategy: "ask-bypass" },
        { match: "ssh blocked-host*", kind: "ssh-auth", strategy: "deny" },
      ],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("deny");
  });

  it("binds socket-bypass approvals to the complete invocation", () => {
    const trusted = resolveAuthExceptionPolicy({
      command: "ssh trusted-host && echo done",
      authCommands: ["ssh trusted-host"],
      kind: "ssh-auth",
      rules: [],
      hasCandidatePaths: false,
      needsSocketFallback: true,
    });
    const other = resolveAuthExceptionPolicy({
      command: "ssh other-host && echo done",
      authCommands: ["ssh other-host"],
      kind: "ssh-auth",
      rules: [],
      hasCandidatePaths: false,
      needsSocketFallback: true,
    });

    expect(trusted.strategy).toBe("ask-bypass");
    expect(other.strategy).toBe("ask-bypass");
    expect(trusted.approvalKey).not.toBe(other.approvalKey);
  });

  it("requires every auth command to match before applying ask-bypass", () => {
    const resolved = resolveAuthExceptionPolicy({
      command: "ssh trusted-host && ssh other-host",
      authCommands: ["ssh trusted-host", "ssh other-host"],
      kind: "ssh-auth",
      rules: [{ match: "ssh trusted-host", kind: "ssh-auth", strategy: "ask-bypass" }],
      hasCandidatePaths: true,
      needsSocketFallback: false,
    });

    expect(resolved.strategy).toBe("ask-unmask");
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
