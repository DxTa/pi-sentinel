import { describe, expect, it } from "vitest";

import type { DecisionRecord, HumanAction } from "./yolo-auto-decision-store";
import { summarizeNeighbours } from "./yolo-auto-neighbours";

const DAY = 86_400_000;
const NOW = 100 * DAY;
const base = Array.from({ length: 46 }, (_, i) => (i % 5) / 10 + 0.05);
const far = base.map((v, i) => (i % 2 === 0 ? 1 - v : 0));

function rec(
  humanAction: HumanAction,
  overrides: Partial<DecisionRecord> = {},
): DecisionRecord {
  return {
    evaluationId: Math.random().toString(36),
    ts: NOW - DAY,
    scope: "ws:aaaa",
    toolName: "bash",
    operation: "exec",
    patternKey: "bash:pytest *",
    features: base,
    hardRuleHit: false,
    modelAction: "prompt",
    humanAction,
    humanTs: NOW - DAY,
    ...overrides,
  };
}

const query = {
  scope: "ws:aaaa",
  toolName: "bash",
  operation: "exec",
  patternKey: "bash:pytest *",
  features: base,
  now: NOW,
};

describe("summarizeNeighbours", () => {
  it("counts exact-key approvals and denials in the workspace scope", () => {
    const summary = summarizeNeighbours([rec("allow_once"), rec("session"), rec("deny")], query);
    expect(summary.workspace).toEqual({ approvals: 2, denials: 1 });
  });

  it("counts only the same pattern key, even when head features are identical", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { patternKey: "bash:pytest-xdist *" }),
      rec("deny", { patternKey: "ls:tests/*" }),
      rec("deny", { patternKey: "bash:curl *", features: far }),
    ], query);
    expect(summary.workspace).toEqual({ approvals: 0, denials: 0 });
  });

  it("ignores hard-rule rows (those prompts belong to the hard rule, not learning)", () => {
    const summary = summarizeNeighbours([rec("deny", { hardRuleHit: true }), rec("allow_once")], query);
    expect(summary.workspace).toEqual({ approvals: 1, denials: 0 });
  });

  it("ignores other tools/operations, unlabelled rows, and decisions older than 30 days", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { toolName: "read", operation: "read" }),
      { ...rec("allow_once"), humanAction: null, humanTs: null },
      rec("allow_once", { humanTs: NOW - 31 * DAY, ts: NOW - 31 * DAY }),
    ], query);
    expect(summary.workspace).toEqual({ approvals: 0, denials: 0 });
    expect(summary.global).toEqual({ approvals: 0, denials: 0, workspaces: 0 });
  });

  it("aggregates other workspaces into global with a distinct workspace count", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { scope: "ws:bbbb" }),
      rec("global", { scope: "ws:bbbb" }),
      rec("allow_once", { scope: "ws:cccc" }),
      rec("deny", { scope: "ws:dddd" }),
      rec("allow_once"),
    ], query);
    expect(summary.workspace).toEqual({ approvals: 1, denials: 0 });
    expect(summary.global).toEqual({ approvals: 3, denials: 1, workspaces: 3 });
  });
});
