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
