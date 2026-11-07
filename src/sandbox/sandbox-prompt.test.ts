import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { promptSandboxGrant, setSandboxYoloHooks } from "./sandbox-prompt";

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

describe("promptSandboxGrant in yolo", () => {
  const log = vi.fn();
  const ctx = (select = vi.fn(async () => "Allow once")) => ({ hasUI: true, cwd: "/repo", ui: { select } }) as never;
  const change = (overrides: Record<string, unknown>) => ({ type: "network", description: "d", values: ["example.com"], ...overrides }) as never;

  beforeEach(() => setSandboxYoloHooks({ isYolo: () => true, log }));
  afterEach(() => { setSandboxYoloHooks(undefined); log.mockClear(); });

  it.each([
    ["network", {}],
    ["plain path", { type: "path", mode: "rw", values: ["/opt/data"] }],
  ])("grants a %s request once without a dialog", async (_name, overrides) => {
    const select = vi.fn(async () => "Deny");
    await expect(promptSandboxGrant(ctx(select), { command: "c", change: change(overrides) }))
      .resolves.toEqual({ action: "allow", duration: "once" });
    expect(select).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith("sandbox_request.yolo_granted_once", expect.objectContaining({ type: overrides.type ?? "network" }));
  });

  it("grants a host rerun once when the caller marks it as a workspace-only rerun", async () => {
    const select = vi.fn(async () => "Deny");
    await expect(promptSandboxGrant(ctx(select), {
      command: "c",
      change: change({ type: "host-bypass", values: ["sandbox-block"] }),
      allowPersistentScopes: false,
      allowSession: false,
      yoloHostRerun: true,
    })).resolves.toEqual({ action: "allow", duration: "once" });
    expect(select).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith("sandbox_request.yolo_granted_once", expect.objectContaining({ type: "host-bypass" }));
  });

  it.each([
    ["auth bypass", { type: "auth-bypass", authKind: "ssh" }],
    ["host bypass", { type: "host-bypass", values: ["git-push"] }],
    ["masked auth path", { type: "path", mode: "ro", authKind: "aws" }],
    ["env grant", { type: "env", cli: "gh" }],
  ])("denies %s without a dialog", async (_name, overrides) => {
    const select = vi.fn(async () => "Allow once");
    await expect(promptSandboxGrant(ctx(select), { command: "c", change: change(overrides) }))
      .resolves.toEqual({ action: "deny" });
    expect(select).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith("sandbox_request.yolo_denied", expect.anything());
  });

  it("grants unscanned folders for the session so bash is not blocked on every command", async () => {
    const select = vi.fn(async () => "Deny");
    await expect(promptSandboxGrant(ctx(select), {
      command: "c",
      change: change({ type: "path", mode: "ro", values: ["/Users/me/dev"] }),
      allowPersistentScopes: false,
      unscannedRoots: true,
    })).resolves.toEqual({ action: "allow", duration: "session" });
    expect(select).not.toHaveBeenCalled();
  });

  it.each([
    ["protected paths", { allowPersistentScopes: false }],
  ])("denies a path request with %s", async (_name, extra) => {
    const select = vi.fn(async () => "Allow once");
    await expect(promptSandboxGrant(ctx(select), { command: "c", change: change({ type: "path", mode: "ro", values: ["/x"] }), ...extra }))
      .resolves.toEqual({ action: "deny" });
    expect(select).not.toHaveBeenCalled();
  });
});

