import { describe, expect, it } from "vitest";

import { PromptWaitTracker, PROMPT_WAIT_STATUS_KEY } from "./prompt-state";

describe("PromptWaitTracker", () => {
  it("sets status and emits blocked state while prompt is active", () => {
    const statuses: Array<{ key: string; value: string | undefined }> = [];
    const events: Array<{ channel: string; payload: unknown }> = [];
    const tracker = new PromptWaitTracker({
      emit(channel, payload) {
        events.push({ channel, payload });
      },
      on() {
        return () => undefined;
      },
    });
    const ctx = {
      hasUI: true,
      ui: {
        setStatus(key: string, value: string | undefined) {
          statuses.push({ key, value });
        },
      },
    };

    const token = tracker.begin(ctx, "Waiting for permission approval");
    tracker.end(ctx, token);

    expect(statuses).toEqual([
      { key: PROMPT_WAIT_STATUS_KEY, value: "Waiting for permission approval" },
      { key: PROMPT_WAIT_STATUS_KEY, value: undefined },
    ]);
    expect(events).toEqual([
      {
        channel: "herdr:blocked",
        payload: { active: true, label: "Waiting for permission approval" },
      },
      {
        channel: "herdr:blocked",
        payload: { active: false, label: "Waiting for permission approval" },
      },
    ]);
  });

  it("restores previous status when nested prompts unwind", () => {
    const statuses: Array<string | undefined> = [];
    const tracker = new PromptWaitTracker();
    const ctx = {
      hasUI: true,
      ui: {
        setStatus(_key: string, value: string | undefined) {
          statuses.push(value);
        },
      },
    };

    const outer = tracker.begin(ctx, "Waiting for sandbox path approval");
    const inner = tracker.begin(ctx, "Waiting for sandbox network approval");
    tracker.end(ctx, inner);
    tracker.end(ctx, outer);

    expect(statuses).toEqual([
      "Waiting for sandbox path approval",
      "Waiting for sandbox network approval",
      "Waiting for sandbox path approval",
      undefined,
    ]);
  });

  it("emits unblock events when cleared with active prompts", () => {
    const events: Array<{ channel: string; payload: unknown }> = [];
    const tracker = new PromptWaitTracker({
      emit(channel, payload) {
        events.push({ channel, payload });
      },
    });
    const ctx = {
      hasUI: true,
      ui: {
        setStatus() {
          return undefined;
        },
      },
    };

    tracker.begin(ctx, "Waiting for secret-read approval");
    tracker.begin(ctx, "Waiting for env exposure approval");
    tracker.clear(ctx);

    expect(events).toEqual([
      {
        channel: "herdr:blocked",
        payload: { active: true, label: "Waiting for secret-read approval" },
      },
      {
        channel: "herdr:blocked",
        payload: { active: true, label: "Waiting for env exposure approval" },
      },
      {
        channel: "herdr:blocked",
        payload: { active: false, label: "Waiting for secret-read approval" },
      },
      {
        channel: "herdr:blocked",
        payload: { active: false, label: "Waiting for env exposure approval" },
      },
    ]);
  });
});
