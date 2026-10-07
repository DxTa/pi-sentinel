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
    audit: false,
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
    expect(summary.workspace).toMatchObject({ approvals: 2, denials: 1 });
  });

  it("counts only the same pattern key, even when head features are identical", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { patternKey: "bash:pytest-xdist *" }),
      rec("deny", { patternKey: "ls:tests/*" }),
      rec("deny", { patternKey: "bash:curl *", features: far }),
    ], query);
    expect(summary.workspace).toMatchObject({ approvals: 0, denials: 0 });
  });

  it("ignores hard-rule rows (those prompts belong to the hard rule, not learning)", () => {
    const summary = summarizeNeighbours([rec("deny", { hardRuleHit: true }), rec("allow_once")], query);
    expect(summary.workspace).toMatchObject({ approvals: 1, denials: 0 });
  });

  it("ignores other tools/operations, unlabelled rows, and decisions older than 30 days", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { toolName: "read", operation: "read" }),
      { ...rec("allow_once"), humanAction: null, humanTs: null },
      rec("allow_once", { humanTs: NOW - 31 * DAY, ts: NOW - 31 * DAY }),
    ], query);
    expect(summary.workspace).toMatchObject({ approvals: 0, denials: 0 });
    expect(summary.global).toMatchObject({ approvals: 0, denials: 0, workspaces: 0 });
  });

  it("aggregates other workspaces into global with a distinct workspace count", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { scope: "ws:bbbb" }),
      rec("global", { scope: "ws:bbbb" }),
      rec("allow_once", { scope: "ws:cccc" }),
      rec("deny", { scope: "ws:dddd" }),
      rec("allow_once"),
    ], query);
    expect(summary.workspace).toMatchObject({ approvals: 1, denials: 0 });
    expect(summary.global).toMatchObject({ approvals: 3, denials: 1, workspaces: 2 });
  });

  it("decays approval weight with a 14-day half-life and counts distinct approval days", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { humanTs: NOW }),
      rec("allow_once", { humanTs: NOW - 14 * DAY }),
      rec("session", { humanTs: NOW - 14 * DAY + 1_000 }),
    ], query);
    expect(summary.workspace.approvalWeight).toBeCloseTo(2, 1);
    expect(summary.workspace.approvalDays).toBe(2);
  });

  it("does not let audit approvals add evidence, but lets audit denials count", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { audit: true }),
      rec("allow_once", { audit: true, scope: "ws:bbbb" }),
      rec("deny", { audit: true, scope: "ws:cccc" }),
    ], query);
    expect(summary.workspace).toMatchObject({ approvals: 0, approvalWeight: 0, approvalDays: 0 });
    expect(summary.global).toMatchObject({ approvals: 0, workspaces: 0, denials: 1, denialWorkspaces: 1 });
  });

  it("lets the latest explicit decision in a scope win, with ties going to the denial", () => {
    const deniedThenApproved = summarizeNeighbours([
      rec("deny", { humanTs: NOW - 2 * DAY }), rec("allow_once", { humanTs: NOW - DAY }),
    ], query);
    const approvedThenDenied = summarizeNeighbours([
      rec("allow_once", { humanTs: NOW - 2 * DAY }), rec("deny", { humanTs: NOW - DAY }),
    ], query);
    const tie = summarizeNeighbours([rec("allow_once"), rec("deny")], query);
    expect(deniedThenApproved.workspace.latestIsDeny).toBe(false);
    expect(approvedThenDenied.workspace.latestIsDeny).toBe(true);
    expect(tie.workspace.latestIsDeny).toBe(true);
  });

  it("counts a denial in another workspace only while that workspace's latest decision is a denial", () => {
    const summary = summarizeNeighbours([
      rec("deny", { scope: "ws:bbbb", humanTs: NOW - 3 * DAY }),
      rec("allow_once", { scope: "ws:bbbb", humanTs: NOW - DAY }),
      rec("deny", { scope: "ws:cccc" }),
    ], query);
    expect(summary.global.denialWorkspaces).toBe(1);
  });

  it("counts only approving workspaces and approval days in the global bucket", () => {
    const summary = summarizeNeighbours([
      rec("allow_once", { scope: "ws:bbbb", humanTs: NOW - DAY }),
      rec("allow_once", { scope: "ws:cccc", humanTs: NOW - 2 * DAY }),
      rec("deny", { scope: "ws:dddd" }),
    ], query);
    expect(summary.global).toMatchObject({ workspaces: 2, approvalDays: 2, denialWorkspaces: 1 });
  });
});
