import { mkdtempSync, statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  featuresFromHeads,
  openDecisionStore,
  patternKeyFor,
  workspaceScope,
} from "./auto-mode-decision-store";
import { AUTO_MODE_LABEL_SCHEMA } from "./auto-mode-label-schema";
import type { AutoModeHeads } from "./auto-mode-policy";

function heads(benign = 0.95): AutoModeHeads {
  const out: Record<string, Record<string, number>> = {};
  for (const [head, labels] of Object.entries(AUTO_MODE_LABEL_SCHEMA)) {
    out[head] = Object.fromEntries(labels.map((label, i) => [label, i === 0 ? 0.9 : 0.01]));
  }
  out.threat!.benign = benign;
  return out as unknown as AutoModeHeads;
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
    const total = Object.values(AUTO_MODE_LABEL_SCHEMA).reduce((n, labels) => n + labels.length, 0);
    expect(features).toHaveLength(total);
    const threatStart = ["injection", "routing", "sensitive_document"]
      .reduce((n, h) => n + AUTO_MODE_LABEL_SCHEMA[h as keyof typeof AUTO_MODE_LABEL_SCHEMA].length, 0);
    expect(features[threatStart + AUTO_MODE_LABEL_SCHEMA.threat.indexOf("benign")]).toBe(0.42);
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
      "audit", "evaluation_id", "features", "hard_rule", "human_action", "human_ts",
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
    [{ toolName: "bash", command: "cd src && rm -rf build" }, "bash:cd *|rm *"],
    [{ toolName: "bash", command: "rm -rf build && cd src && rm x" }, "bash:cd *|rm *"],
    [{ toolName: "bash", command: "for f in a b; do rm $f; done" }, "bash:rm *"],
    [{ toolName: "bash", command: "bash -c 'cd x && pytest -q'" }, "bash:cd *|pytest *"],
    [{ toolName: "bash", command: "FOO=1" }, "bash:*"],
  ])("derives a coarse key for %j", (input, expected) => {
    expect(patternKeyFor(input)).toBe(expected);
  });

  it.each(['eval "$x"', "ls && python3 -c 'print(1)'", 'echo "$(id)"', "cat a | sh"])(
    "gives unreadable Bash %j no key, so history can never convert it",
    (command) => {
      expect(patternKeyFor({ toolName: "bash", command })).toBeUndefined();
    },
  );
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

describe("audit flag and legacy labels", () => {
  const open = () => openDecisionStore(join(mkdtempSync(join(tmpdir(), "decision-store-")), "d.db"));

  it("persists whether an evaluation was an audit sample", () => {
    const store = open();
    store.recordEvaluation({ ...row("audited"), audit: true });
    store.recordEvaluation(row("plain"));
    const scope = workspaceScope("/work/repo");
    const byId = Object.fromEntries(store.listDecisions(scope).map((r) => [r.evaluationId, r.audit]));
    store.close();
    expect(byId).toEqual({ audited: true, plain: false });
  });

  it("adds the audit column to a database created before it existed", () => {
    const dbPath = join(mkdtempSync(join(tmpdir(), "decision-store-")), "legacy.db");
    const legacy = new DatabaseSync(dbPath);
    legacy.exec(`CREATE TABLE decisions (
      evaluation_id TEXT PRIMARY KEY, ts INTEGER NOT NULL, scope TEXT NOT NULL, tool TEXT NOT NULL,
      operation TEXT NOT NULL, pattern_key TEXT NOT NULL, features TEXT NOT NULL, hard_rule INTEGER NOT NULL,
      model_action TEXT NOT NULL, human_action TEXT, human_ts INTEGER);
      INSERT INTO decisions VALUES ('old', 5000, 'ws:x', 'bash', 'exec', 'bash:pytest *', '[]', 0, 'prompt', 'allow_once', 9000);`);
    legacy.close();
    const store = openDecisionStore(dbPath);
    const [saved] = store.listLabelled("bash", "exec", 0);
    store.close();
    expect(saved).toMatchObject({ evaluationId: "old", audit: false });
  });

  it("ignores denials recorded faster than a person can answer, but keeps fast approvals", () => {
    const store = open();
    for (const id of ["fast-deny", "slow-deny", "fast-allow"]) store.recordEvaluation({ ...row(id), ts: 5_000 });
    store.recordHumanDecision("fast-deny", "deny", 5_000);
    store.recordHumanDecision("slow-deny", "deny", 7_000);
    store.recordHumanDecision("fast-allow", "allow_once", 5_100);
    const ids = store.listLabelled("bash", "exec", 0).map((r) => r.evaluationId).sort();
    store.close();
    expect(ids).toEqual(["fast-allow", "slow-deny"]);
  });
});
