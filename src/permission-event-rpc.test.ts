import { describe, expect, it, vi } from "vitest";

import {
  PERMISSIONS_RPC_PROMPT_CHANNEL,
  type PermissionEventBus,
} from "./permission-events";
import { registerPermissionRpcHandlers } from "./permission-event-rpc";
import { PromptWaitTracker } from "./prompt-state";

describe("registerPermissionRpcHandlers", () => {
  it("tracks status while forwarded permission prompt waits for user input", async () => {
    const emitted: Array<{ channel: string; payload: unknown }> = [];
    const listeners = new Map<string, (data: unknown) => void>();
    const bus: PermissionEventBus = {
      emit(channel, payload) {
        emitted.push({ channel, payload });
      },
      on(channel, handler) {
        listeners.set(channel, handler);
        return () => listeners.delete(channel);
      },
    };
    const statuses: Array<string | undefined> = [];
    const tracker = new PromptWaitTracker(bus);

    registerPermissionRpcHandlers(bus, {
      promptWaitTracker: tracker,
      getPermissionManager: () => ({
        checkPermission: () => ({ state: "allow", matchedPattern: null, origin: null }),
      }),
      getSessionRules: () => [],
      getRuntimeContext: () => ({
        hasUI: true,
        ui: {
          setStatus(_key: string, value: string | undefined) {
            statuses.push(value);
          },
        },
      }) as never,
      requestPermissionDecisionFromUi: async () => ({
        approved: true,
        state: "approved_for_session",
      }),
      writeReviewLog: () => undefined,
    });

    const requestId = "rpc-1";
    listeners.get(PERMISSIONS_RPC_PROMPT_CHANNEL)?.({
      requestId,
      surface: "bash",
      value: "cat /tmp/example.txt",
      message: "Need permission",
      agentName: "pi",
    });

    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(statuses).toEqual([
      "Waiting for permission approval",
      undefined,
    ]);
    expect(emitted).toContainEqual({
      channel: "herdr:blocked",
      payload: { active: true, label: "Waiting for permission approval" },
    });
    expect(emitted).toContainEqual({
      channel: "herdr:blocked",
      payload: { active: false, label: "Waiting for permission approval" },
    });
    expect(emitted).toContainEqual({
      channel: `${PERMISSIONS_RPC_PROMPT_CHANNEL}:reply:${requestId}`,
      payload: {
        success: true,
        protocolVersion: 1,
        data: {
          approved: true,
          state: "approved_for_session",
        },
      },
    });
  });
  it("approves a prompt request in yolo without a dialog, even with no UI", async () => {
    const emitted: Array<{ channel: string; payload: unknown }> = [];
    const listeners = new Map<string, (data: unknown) => void>();
    const bus: PermissionEventBus = {
      emit(channel, payload) {
        emitted.push({ channel, payload });
      },
      on(channel, handler) {
        listeners.set(channel, handler);
        return () => listeners.delete(channel);
      },
    };
    const requestPermissionDecisionFromUi = vi.fn();
    const reviewLog = vi.fn();

    registerPermissionRpcHandlers(bus, {
      promptWaitTracker: new PromptWaitTracker(bus),
      getPermissionManager: () => ({
        checkPermission: () => ({ state: "allow", matchedPattern: null, origin: null }),
      }),
      getSessionRules: () => [],
      getRuntimeContext: () => ({ hasUI: false }) as never,
      isYolo: () => true,
      requestPermissionDecisionFromUi,
      writeReviewLog: reviewLog,
    });

    listeners.get(PERMISSIONS_RPC_PROMPT_CHANNEL)?.({
      requestId: "rpc-yolo",
      surface: "bash",
      value: "ls",
      message: "Need permission",
      agentName: "pi",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(requestPermissionDecisionFromUi).not.toHaveBeenCalled();
    expect(JSON.stringify(emitted)).toContain('"approved":true');
    expect(reviewLog).toHaveBeenCalledWith("permission_request.rpc_yolo_approved", expect.anything());
  });
});
