import { readForwardedPermissionResponse } from "./io";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  createPermissionForwardingLocation,
  type ForwardedPermissionRequest,
} from "../permission-forwarding";
import { type PermissionEventBus } from "../permission-events";
import { PromptWaitTracker } from "../prompt-state";
import { processForwardedPermissionRequests } from "./polling";

describe("processForwardedPermissionRequests", () => {
  it("tracks blocked/status while parent session answers subagent permission prompt", async () => {
    const forwardingDir = mkdtempSync(join(tmpdir(), "forwarded-permission-"));
    const location = createPermissionForwardingLocation(forwardingDir, "parent-session");
    mkdirSync(location.requestsDir, { recursive: true });
    mkdirSync(location.responsesDir, { recursive: true });

    const request: ForwardedPermissionRequest = {
      id: `${Date.now()}-subagent-${process.pid}`,
      createdAt: Date.now(),
      requesterSessionId: "child-session",
      targetSessionId: "parent-session",
      requesterAgentName: "worker",
      message: "Need permission",
    };
    writeFileSync(
      join(location.requestsDir, `${request.id}.json`),
      JSON.stringify(request),
      "utf-8",
    );

    const statuses: Array<string | undefined> = [];
    const emitted: Array<{ channel: string; payload: unknown }> = [];
    const bus: PermissionEventBus = {
      emit(channel, payload) {
        emitted.push({ channel, payload });
      },
      on() {
        return () => undefined;
      },
    };
    const promptWaitTracker = new PromptWaitTracker(bus);

    await processForwardedPermissionRequests(
      {
        hasUI: true,
        ui: {
          setStatus(_key: string, value: string | undefined) {
            statuses.push(value);
          },
        },
        sessionManager: {
          getSessionId() {
            return "parent-session";
          },
        },
      } as never,
      {
        forwardingDir,
        subagentSessionsDir: "/tmp/subagents",
        logger: {
          writeReviewLog() {
            return undefined;
          },
          writeDebugLog() {
            return undefined;
          },
        },
        promptWaitTracker,
        writeReviewLog() {
          return undefined;
        },
        requestPermissionDecisionFromUi: async () => ({
          approved: true,
          state: "approved_for_session",
        }),
        shouldAutoApprove: () => false,
      },
    );

    expect(statuses).toEqual([
      "Waiting for subagent permission approval",
      undefined,
    ]);
    expect(emitted).toEqual([
      {
        channel: "herdr:blocked",
        payload: {
          active: true,
          label: "Waiting for subagent permission approval",
        },
      },
      {
        channel: "herdr:blocked",
        payload: {
          active: false,
          label: "Waiting for subagent permission approval",
        },
      },
    ]);

    const response = JSON.parse(
      readFileSync(join(location.responsesDir, `${request.id}.json`), "utf-8"),
    ) as { approved: boolean; state: string; responderSessionId: string };
    expect(response).toMatchObject({
      approved: true,
      state: "approved_for_session",
      responderSessionId: "parent-session",
    });
  });

  it("passes forwarded request metadata to shouldAutoApprove", async () => {
    const forwardingDir = mkdtempSync(join(tmpdir(), "forwarded-permission-"));
    const location = createPermissionForwardingLocation(forwardingDir, "parent-session");
    mkdirSync(location.requestsDir, { recursive: true });
    mkdirSync(location.responsesDir, { recursive: true });

    const request: ForwardedPermissionRequest = {
      id: `${Date.now()}-subagent-${process.pid}`,
      createdAt: Date.now(),
      requesterSessionId: "child-session",
      targetSessionId: "parent-session",
      requesterAgentName: "worker",
      message: "Need permission",
      toolName: "bash",
      command: "git push origin main",
    } as any;
    writeFileSync(
      join(location.requestsDir, `${request.id}.json`),
      JSON.stringify(request),
      "utf-8",
    );

    const shouldAutoApprove = vi.fn(() => false);
    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved_for_session" as const,
    }));

    await processForwardedPermissionRequests(
      {
        hasUI: true,
        ui: {
          setStatus() {},
        },
        sessionManager: {
          getSessionId() {
            return "parent-session";
          },
        },
      } as never,
      {
        forwardingDir,
        subagentSessionsDir: "/tmp/subagents",
        logger: {
          writeReviewLog() {
            return undefined;
          },
          writeDebugLog() {
            return undefined;
          },
        },
        promptWaitTracker: new PromptWaitTracker({ emit() {} }),
        writeReviewLog() {
          return undefined;
        },
        requestPermissionDecisionFromUi,
        shouldAutoApprove,
      },
    );

    expect(shouldAutoApprove).toHaveBeenCalledWith(
      expect.objectContaining({
        toolName: "bash",
        command: "git push origin main",
      }),
    );
    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
  });

  it("forces a prompt when requester already matched a yolo exception", async () => {
    const forwardingDir = mkdtempSync(join(tmpdir(), "forwarded-permission-"));
    const location = createPermissionForwardingLocation(forwardingDir, "parent-session");
    mkdirSync(location.requestsDir, { recursive: true });
    mkdirSync(location.responsesDir, { recursive: true });

    const request: ForwardedPermissionRequest = {
      id: `${Date.now()}-subagent-${process.pid}`,
      createdAt: Date.now(),
      requesterSessionId: "child-session",
      targetSessionId: "parent-session",
      requesterAgentName: "worker",
      message: "Need permission",
      toolName: "bash",
      command: "git push origin main",
      forcePromptInYolo: true,
    } as any;
    writeFileSync(
      join(location.requestsDir, `${request.id}.json`),
      JSON.stringify(request),
      "utf-8",
    );

    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved_for_session" as const,
    }));

    await processForwardedPermissionRequests(
      {
        hasUI: true,
        ui: {
          setStatus() {},
        },
        sessionManager: {
          getSessionId() {
            return "parent-session";
          },
        },
      } as never,
      {
        forwardingDir,
        subagentSessionsDir: "/tmp/subagents",
        logger: {
          writeReviewLog() {
            return undefined;
          },
          writeDebugLog() {
            return undefined;
          },
        },
        promptWaitTracker: new PromptWaitTracker({ emit() {} }),
        writeReviewLog() {
          return undefined;
        },
        requestPermissionDecisionFromUi,
        shouldAutoApprove: vi.fn(() => true),
      },
    );

    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
    const response = JSON.parse(
      readFileSync(join(location.responsesDir, `${request.id}.json`), "utf-8"),
    ) as { approved: boolean; state: string };
    expect(response).toMatchObject({
      approved: true,
      state: "approved_for_session",
    });
  });

  it("forces a prompt for non-bash forwarded writes marked forcePromptInYolo", async () => {
    const forwardingDir = mkdtempSync(join(tmpdir(), "forwarded-permission-"));
    const location = createPermissionForwardingLocation(forwardingDir, "parent-session");
    mkdirSync(location.requestsDir, { recursive: true });
    mkdirSync(location.responsesDir, { recursive: true });

    const request: ForwardedPermissionRequest = {
      id: `${Date.now()}-subagent-${process.pid}`,
      createdAt: Date.now(),
      requesterSessionId: "child-session",
      targetSessionId: "parent-session",
      requesterAgentName: "worker",
      message: "Need permission",
      toolName: "write",
      forcePromptInYolo: true,
    } as any;
    writeFileSync(
      join(location.requestsDir, `${request.id}.json`),
      JSON.stringify(request),
      "utf-8",
    );

    const requestPermissionDecisionFromUi = vi.fn(async () => ({
      approved: true,
      state: "approved_for_session" as const,
      humanDecided: true as const,
    }));

    await processForwardedPermissionRequests(
      {
        hasUI: true,
        ui: {
          setStatus() {},
        },
        sessionManager: {
          getSessionId() {
            return "parent-session";
          },
        },
      } as never,
      {
        forwardingDir,
        subagentSessionsDir: "/tmp/subagents",
        logger: {
          writeReviewLog() {
            return undefined;
          },
          writeDebugLog() {
            return undefined;
          },
        },
        promptWaitTracker: new PromptWaitTracker({ emit() {} }),
        writeReviewLog() {
          return undefined;
        },
        requestPermissionDecisionFromUi,
        shouldAutoApprove: vi.fn(() => true),
      },
    );

    expect(requestPermissionDecisionFromUi).toHaveBeenCalledOnce();
    const response = JSON.parse(
      readFileSync(join(location.responsesDir, `${request.id}.json`), "utf-8"),
    ) as { approved: boolean; state: string };
    expect(response).toMatchObject({
      approved: true,
      state: "approved_for_session",
      humanDecided: true,
    });
  });
});

describe("readForwardedPermissionResponse", () => {
  it("keeps the human-decided flag only when the responder set it", () => {
    const dir = mkdtempSync(join(tmpdir(), "forwarded-response-"));
    const write = (name: string, extra: object) => {
      const path = join(dir, name);
      writeFileSync(path, JSON.stringify({
        approved: false, state: "denied", responderSessionId: "parent", respondedAt: 1, ...extra,
      }), "utf-8");
      return path;
    };
    expect(readForwardedPermissionResponse(null, write("human.json", { humanDecided: true })))
      .toMatchObject({ humanDecided: true });
    expect(readForwardedPermissionResponse(null, write("system.json", {}))).not.toHaveProperty("humanDecided");
    expect(readForwardedPermissionResponse(null, write("spoof.json", { humanDecided: "yes" })))
      .not.toHaveProperty("humanDecided");
  });
});
