import { describe, expect, it, vi } from "vitest";

import { promptSandboxGrant } from "./sandbox-prompt";

describe("promptSandboxGrant", () => {
  it("maps workspace choice to persistent workspace scope", async () => {
    const ctx = {
      hasUI: true,
      cwd: "/repo",
      ui: {
        select: vi.fn(async () => "Allow for this workspace"),
      },
    } as never;

    await expect(
      promptSandboxGrant(ctx, {
        command: "curl https://example.com",
        change: {
          type: "network",
          description: "need network",
          values: ["example.com"],
        },
      }),
    ).resolves.toEqual({ action: "allow", duration: "always", scope: "workspace" });
  });

  it("maps global choice to persistent global scope", async () => {
    const ctx = {
      hasUI: true,
      ui: {
        select: vi.fn(async () => "Allow globally"),
      },
    } as never;

    await expect(
      promptSandboxGrant(ctx, {
        command: "curl https://example.com",
        change: {
          type: "network",
          description: "need network",
          values: ["example.com"],
        },
      }),
    ).resolves.toEqual({ action: "allow", duration: "always", scope: "global" });
  });
});


describe("host toolchain prompt", () => {
  it.each(["Allow once", "Allow for session", "Allow globally", undefined])(
    "restricts a one-time host prompt to its displayed choices (choice=%s)", async (choice) => {
      const select = vi.fn(async () => choice);
      const ctx = { hasUI: true, cwd: "/repo", ui: { select } } as never;
      const result = await promptSandboxGrant(ctx, {
        command: "git push origin main",
        change: { type: "host-bypass", description: "SRT egress failed", values: ["git-push"] },
        allowPersistentScopes: false,
        allowSession: false,
      });
      expect(result).toEqual(choice === "Allow once"
        ? { action: "allow", duration: "once", scope: undefined }
        : { action: "deny" });
      expect(select).toHaveBeenCalledWith(
        expect.stringContaining("One-time Host Execution"), ["Allow once", "Deny"],
      );
    },
  );

  it("offers only once/session/deny choices", async () => {
    const select = vi.fn(async () => "Allow for session");
    const ctx = {
      hasUI: true,
      cwd: "/repo",
      ui: { select },
    } as never;

    await expect(
      promptSandboxGrant(ctx, {
        command: "python3 -m venv .venv",
        change: {
          type: "host-bypass",
          description: "SRT unavailable",
          values: ["host-toolchain"],
        },
        allowPersistentScopes: false,
      }),
    ).resolves.toEqual({ action: "allow", duration: "session" });
    expect(select).toHaveBeenCalledWith(
      expect.stringContaining("Host Toolchain Required"),
      ["Allow once", "Allow for session", "Deny"],
    );
  });
});

describe("host-bypass persistent scopes", () => {
  it("offers workspace and global scopes when persistent scopes are allowed", async () => {
    const select = vi.fn(async () => "Allow for this workspace");
    const ctx = { hasUI: true, cwd: "/repo", ui: { select } } as never;

    await expect(
      promptSandboxGrant(ctx, {
        command: "docker build -t x .",
        change: { type: "host-bypass", description: "SRT denied buildx", values: ["docker build"] },
        allowPersistentScopes: true,
      }),
    ).resolves.toEqual({ action: "allow", duration: "always", scope: "workspace" });
    expect(select).toHaveBeenCalledWith(
      expect.any(String),
      ["Allow once", "Allow for session", "Allow for this workspace", "Allow globally", "Deny"],
    );
  });
});
