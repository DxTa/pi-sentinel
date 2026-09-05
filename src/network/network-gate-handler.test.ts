import { describe, expect, it, vi } from "vitest";

import { clearSessionNetworkApprovals, handleNetworkToolCall } from "./network-gate-handler";
import { PromptWaitTracker } from "../prompt-state";

describe("handleNetworkToolCall", () => {
  it("keeps explicit localhost denies ahead of sandbox network access", async () => {
    clearSessionNetworkApprovals();
    const select = vi.fn();
    const result = await handleNetworkToolCall(
      {
        toolName: "bash",
        input: { command: "curl http://localhost:8080" },
      } as never,
      { hasUI: true, cwd: "/repo", ui: { select } } as never,
      {
        getNetworkConfig: () => ({
          enabled: true,
          unknownDomains: "allow",
          deniedDomains: ["localhost"],
        }),
        getAgentDir: () => "/agent",
      },
    );

    expect(result).toMatchObject({ block: true });
    expect(select).not.toHaveBeenCalled();
  });

  it("reports blocked while waiting for domain approval", async () => {
    clearSessionNetworkApprovals();
    const events: Array<{ channel: string; payload: unknown }> = [];
    const promptWaitTracker = new PromptWaitTracker({
      emit(channel, payload) {
        events.push({ channel, payload });
      },
    });
    let resolveChoice!: (choice: string) => void;
    const choice = new Promise<string>((resolve) => {
      resolveChoice = resolve;
    });
    const ctx = {
      hasUI: true,
      cwd: "/repo",
      ui: {
        setStatus: vi.fn(),
        select: vi.fn(() => choice),
      },
    } as never;

    const pending = handleNetworkToolCall(
      {
        toolName: "bash",
        input: { command: "curl https://api.example.com" },
      } as never,
      ctx,
      {
        getNetworkConfig: () => ({ enabled: true, unknownDomains: "ask" }),
        getAgentDir: () => "/agent",
        promptWaitTracker,
      } as never,
    );

    expect(events).toEqual([{
      channel: "herdr:blocked",
      payload: { active: true, label: "Waiting for domain approval" },
    }]);

    resolveChoice("Allow once");
    await pending;

    expect(events.at(-1)).toEqual({
      channel: "herdr:blocked",
      payload: { active: false, label: "Waiting for domain approval" },
    });
  });

  it("persists project-scoped wildcard approval for requested host", async () => {
    clearSessionNetworkApprovals();
    const persistNetworkGrant = vi.fn();
    const ctx = {
      hasUI: true,
      cwd: "/repo",
      ui: {
        select: vi.fn(async (_title: string, options: string[]) => {
          expect(options).toContain("Allow *.api.example.com for this project");
          expect(options).toContain("Allow *.example.com for this project");
          return "Allow *.api.example.com for this project";
        }),
      },
    } as never;

    const result = await handleNetworkToolCall(
      {
        toolName: "bash",
        input: { command: "curl https://api.example.com" },
      } as never,
      ctx,
      {
        getNetworkConfig: () => ({ enabled: true, unknownDomains: "ask" }),
        getAgentDir: () => "/agent",
        persistNetworkGrant,
      },
    );

    expect(result).toEqual({ approvedDomains: ["api.example.com"] });
    expect(persistNetworkGrant).toHaveBeenCalledWith(
      "*.api.example.com",
      "workspace",
    );
  });

  it("persists global parent-domain wildcard approval", async () => {
    clearSessionNetworkApprovals();
    const persistNetworkGrant = vi.fn();
    const ctx = {
      hasUI: true,
      cwd: "/repo",
      ui: {
        select: vi.fn(async () => "Allow *.example.com globally"),
      },
    } as never;

    const result = await handleNetworkToolCall(
      {
        toolName: "bash",
        input: { command: "curl https://api.example.com" },
      } as never,
      ctx,
      {
        getNetworkConfig: () => ({ enabled: true, unknownDomains: "ask" }),
        getAgentDir: () => "/agent",
        persistNetworkGrant,
      },
    );

    expect(result).toEqual({ approvedDomains: ["api.example.com"] });
    expect(persistNetworkGrant).toHaveBeenCalledWith(
      "*.example.com",
      "global",
    );
  });

  it("distinguishes multi-domain wildcard approvals", async () => {
    clearSessionNetworkApprovals();
    const persistNetworkGrant = vi.fn();
    const ctx = {
      hasUI: true,
      cwd: "/repo",
      ui: {
        select: vi.fn(async (_title: string, options: string[]) => {
          expect(new Set(options).size).toBe(options.length);
          expect(options).toContain(
            "Allow *.api.one.example.com, *.api.two.example.com for this project",
          );
          return "Allow *.api.one.example.com, *.api.two.example.com for this project";
        }),
      },
    } as never;

    await handleNetworkToolCall(
      {
        toolName: "bash",
        input: {
          command: "curl https://api.one.example.com https://api.two.example.com",
        },
      } as never,
      ctx,
      {
        getNetworkConfig: () => ({ enabled: true, unknownDomains: "ask" }),
        getAgentDir: () => "/agent",
        persistNetworkGrant,
      },
    );

    expect(persistNetworkGrant).toHaveBeenCalledWith(
      "*.api.one.example.com",
      "workspace",
    );
    expect(persistNetworkGrant).toHaveBeenCalledWith(
      "*.api.two.example.com",
      "workspace",
    );
  });

  it("persists project-scoped denials", async () => {
    clearSessionNetworkApprovals();
    const persistNetworkGrant = vi.fn();
    const ctx = {
      hasUI: true,
      cwd: "/repo",
      ui: {
        select: vi.fn(async () => "Deny api.example.com for this project"),
      },
    } as never;

    const result = await handleNetworkToolCall(
      {
        toolName: "bash",
        input: { command: "curl https://api.example.com" },
      } as never,
      ctx,
      {
        getNetworkConfig: () => ({ enabled: true, unknownDomains: "ask" }),
        getAgentDir: () => "/agent",
        persistNetworkGrant,
      },
    );

    expect(result).toMatchObject({ block: true });
    expect(persistNetworkGrant).toHaveBeenCalledWith(
      "api.example.com",
      "workspace",
      "deny",
    );
  });
});
