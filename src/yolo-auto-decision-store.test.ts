import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  featuresFromHeads,
  openDecisionStore,
  patternKeyFor,
  workspaceScope,
} from "./yolo-auto-decision-store";
import { YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema";
import type { YoloAutoHeads } from "./yolo-auto-policy";

function heads(benign = 0.95): YoloAutoHeads {
  const out: Record<string, Record<string, number>> = {};
  for (const [head, labels] of Object.entries(YOLO_AUTO_LABEL_SCHEMA)) {
    out[head] = Object.fromEntries(labels.map((label, i) => [label, i === 0 ? 0.9 : 0.01]));
  }
  out.threat!.benign = benign;
  return out as unknown as YoloAutoHeads;
}

const row = (evaluationId: string) => ({
  evaluationId,
  ts: 1_000,
  scope: workspaceScope("/work/repo"),
  toolName: "bash",
  operation: "exec" as const,
  patternKey: "pytest *",
  heads: heads(),
  hardRuleHit: false,
  modelAction: "prompt" as const,
});

describe("featuresFromHeads", () => {
  it("flattens every head label in schema order", () => {
    const features = featuresFromHeads(heads(0.42));
    const total = Object.values(YOLO_AUTO_LABEL_SCHEMA).reduce((n, labels) => n + labels.length, 0);
    expect(features).toHaveLength(total);
    const threatStart = ["injection", "routing", "sensitive_document"]
      .reduce((n, h) => n + YOLO_AUTO_LABEL_SCHEMA[h as keyof typeof YOLO_AUTO_LABEL_SCHEMA].length, 0);
    expect(features[threatStart + YOLO_AUTO_LABEL_SCHEMA.threat.indexOf("benign")]).toBe(0.42);
  });
});

describe("workspaceScope", () => {
  it("hashes the workspace path and never exposes it", () => {
    const scope = workspaceScope("/work/repo");
    expect(scope).toMatch(/^ws:[0-9a-f]{16}$/);
    expect(scope).toBe(workspaceScope("/work/repo"));
    expect(scope).not.toBe(workspaceScope("/work/other"));
  });
});

describe("openDecisionStore", () => {
  it("creates an owner-only database and persists human decisions across reopen", () => {
    const dir = join(mkdtempSync(join(tmpdir(), "decision-store-")), "nested");
    const dbPath = join(dir, "decisions.db");
    const store = openDecisionStore(dbPath);
    store.recordEvaluation(row("eval-1"));
    expect(store.recordHumanDecision("eval-1", "deny", 2_000)).toBe(true);
    expect(store.recordHumanDecision("missing", "allow_once", 2_000)).toBe(false);
    store.close();

    expect(statSync(dbPath).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);

    const reopened = openDecisionStore(dbPath);
    const [saved] = reopened.listDecisions(workspaceScope("/work/repo"));
    reopened.close();
    expect(saved).toMatchObject({
      evaluationId: "eval-1",
      toolName: "bash",
      operation: "exec",
      patternKey: "pytest *",
      modelAction: "prompt",
      humanAction: "deny",
      humanTs: 2_000,
      hardRuleHit: false,
    });
    expect(saved?.features).toHaveLength(featuresFromHeads(heads()).length);
  });

  it("keeps only structured columns (no raw request text)", () => {
    const store = openDecisionStore(join(mkdtempSync(join(tmpdir(), "decision-store-")), "d.db"));
    expect(store.columnNames().sort()).toEqual([
      "evaluation_id", "features", "hard_rule", "human_action", "human_ts",
      "model_action", "operation", "pattern_key", "scope", "tool", "ts",
    ]);
    store.close();
  });
});

describe("patternKeyFor", () => {
  it.each([
    [{ toolName: "bash", command: "pytest tests -q" }, "bash:pytest *"],
    [{ toolName: "read", workspaceRelativePath: "src/core/api.py" }, "read:src/*.py"],
    [{ toolName: "write", workspaceRelativePath: "notes.txt" }, "write:./*.txt"],
    [{ toolName: "ls", workspaceRelativePath: "tests" }, "ls:tests/*"],
    [{ toolName: "read" }, "read:*"],
  ])("derives a coarse key for %j", (input, expected) => {
    expect(patternKeyFor(input)).toBe(expected);
  });
});

describe("host Bash decisions", () => {
  it("counts exact workspace/key approvals and denials since the cutoff", () => {
    const store = openDecisionStore(join(mkdtempSync(join(tmpdir(), "decision-store-")), "d.db"));
    const scope = workspaceScope("/work/repo");
    store.recordHostBashDecision(scope, "host-bash:a", "allow", 2_000);
    store.recordHostBashDecision(scope, "host-bash:a", "allow", 3_000);
    store.recordHostBashDecision(scope, "host-bash:a", "deny", 4_000);
    store.recordHostBashDecision(scope, "host-bash:b", "allow", 4_000);

    expect(store.getHostBashDecisionCounts(scope, "host-bash:a", 3_000)).toEqual({ approvals: 1, denials: 1 });
    expect(store.getHostBashDecisionCounts(workspaceScope("/other"), "host-bash:a", 0)).toEqual({ approvals: 0, denials: 0 });
    store.close();
  });
});

describe("listLabelled", () => {
  it("returns labelled rows for one tool/operation across scopes since a timestamp", () => {
    const store = openDecisionStore(join(mkdtempSync(join(tmpdir(), "decision-store-")), "d.db"));
    store.recordEvaluation({ ...row("a"), ts: 5_000 });
    store.recordEvaluation({ ...row("b"), ts: 5_000, scope: workspaceScope("/other") });
    store.recordEvaluation({ ...row("c"), ts: 5_000 });
    store.recordEvaluation({ ...row("d"), ts: 5_000, toolName: "read", operation: "read" });
    store.recordEvaluation({ ...row("old"), ts: 10 });
    for (const id of ["a", "b", "d", "old"]) store.recordHumanDecision(id, "allow_once", id === "old" ? 20 : 6_000);
    const ids = store.listLabelled("bash", "exec", 1_000).map((r) => r.evaluationId).sort();
    store.close();
    expect(ids).toEqual(["a", "b"]);
  });
});
