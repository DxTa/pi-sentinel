/**
 * Local store of model evaluations joined to human decisions (D16).
 * Holds structured features only: head probabilities, tool/operation,
 * a coarse pattern key, and a hashed workspace scope. No raw request text.
 */
import { createHash } from "node:crypto";
import { chmodSync, closeSync, mkdirSync, openSync } from "node:fs";
import { dirname, extname } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { bashInnerCommands } from "./bash-segments";
import { suggestBashPattern } from "./pattern-suggest";
import { YOLO_AUTO_LABEL_SCHEMA, type YoloAutoHeadName } from "./yolo-auto-label-schema";
import type { YoloAutoHeads } from "./yolo-auto-policy";

export type HumanAction = "allow_once" | "session" | "workspace" | "global" | "deny";

export interface EvaluationRow {
  evaluationId: string;
  ts: number;
  scope: string;
  toolName: string;
  operation: string;
  patternKey: string;
  heads: YoloAutoHeads;
  hardRuleHit: boolean;
  modelAction: "allow" | "prompt";
  /** True when the evaluation was an audit sample; its approval adds no allow evidence. */
  audit?: boolean;
}

export interface DecisionRecord extends Omit<EvaluationRow, "heads" | "audit"> {
  features: number[];
  audit: boolean;
  humanAction: HumanAction | null;
  humanTs: number | null;
}

export interface DecisionStore {
  recordEvaluation(row: EvaluationRow): void;
  /** Returns false when the evaluation is unknown. */
  recordHumanDecision(evaluationId: string, action: HumanAction, ts: number): boolean;
  listDecisions(scope: string): DecisionRecord[];
  /** Labelled rows for one tool/operation across all scopes, decided at or after `since`. */
  listLabelled(toolName: string, operation: string, since: number): DecisionRecord[];
  columnNames(): string[];
  close(): void;
}

const HEAD_ORDER = Object.keys(YOLO_AUTO_LABEL_SCHEMA) as YoloAutoHeadName[];

export function featuresFromHeads(heads: YoloAutoHeads): number[] {
  return HEAD_ORDER.flatMap((head) => {
    const probs = (heads as Record<string, Record<string, number>>)[head] ?? {};
    return YOLO_AUTO_LABEL_SCHEMA[head].map((label) => probs[label] ?? 0);
  });
}

export function workspaceScope(workspacePath: string): string {
  return "ws:" + createHash("sha256").update(workspacePath).digest("hex").slice(0, 16);
}

export const GLOBAL_SCOPE = "global";

/** Earlier versions stored failures as human denials, always within milliseconds. */
const MIN_HUMAN_DENIAL_MS = 1_000;

const LIST_TOOLS = new Set(["ls", "find", "grep"]);

/** Coarse, low-leakage key: bash command prefix or tool + top-level dir + extension. */
/*
 * Bash keys list every inner command, so a pattern approved for `cd *` never
 * covers `cd x && rm y`. Code that cannot be read gets no key: history must not
 * convert it.
 */
export function patternKeyFor(input: {
  toolName: string;
  command?: string;
  workspaceRelativePath?: string;
}): string | undefined {
  if (input.toolName === "bash") {
    const inner = bashInnerCommands(input.command ?? "");
    if (!inner || inner.opaque) return undefined;
    const patterns = new Set(inner.commands.map((command) => suggestBashPattern(command) || "*"));
    return `bash:${[...patterns].sort().join("|") || "*"}`;
  }
  const path = input.workspaceRelativePath;
  if (!path) return `${input.toolName}:*`;
  const segments = path.split("/").filter(Boolean);
  if (LIST_TOOLS.has(input.toolName)) return `${input.toolName}:${segments[0] ?? "."}/*`;
  const top = segments.length > 1 ? segments[0] : ".";
  return `${input.toolName}:${top}/*${extname(path)}`;
}

interface Row {
  evaluation_id: string; ts: number; scope: string; tool: string; operation: string;
  pattern_key: string; features: string; hard_rule: number; model_action: string;
  audit: number; human_action: string | null; human_ts: number | null;
}

function initSchema(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS decisions (
    evaluation_id TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    scope TEXT NOT NULL,
    tool TEXT NOT NULL,
    operation TEXT NOT NULL,
    pattern_key TEXT NOT NULL,
    features TEXT NOT NULL,
    hard_rule INTEGER NOT NULL,
    model_action TEXT NOT NULL,
    audit INTEGER NOT NULL DEFAULT 0,
    human_action TEXT,
    human_ts INTEGER
  );
  CREATE INDEX IF NOT EXISTS decisions_scope_key ON decisions(scope, tool, operation, pattern_key);`);
  const columns = db.prepare("PRAGMA table_info(decisions)").all() as { name: string }[];
  if (!columns.some((column) => column.name === "audit")) {
    try {
      db.exec("ALTER TABLE decisions ADD COLUMN audit INTEGER NOT NULL DEFAULT 0");
    } catch (error) {
      // Another Pi session may have added the column between our check and this statement.
      if (!/duplicate column name/i.test(error instanceof Error ? error.message : "")) throw error;
    }
  }
}

export function openDecisionStore(dbPath: string): DecisionStore {
  mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
  chmodSync(dirname(dbPath), 0o700);
  closeSync(openSync(dbPath, "a", 0o600));
  chmodSync(dbPath, 0o600);
  const db = new DatabaseSync(dbPath);
  // Several Pi sessions share one store; wait briefly instead of failing on lock.
  db.exec("PRAGMA busy_timeout = 2000;");
  initSchema(db);

  const insert = db.prepare(`INSERT OR REPLACE INTO decisions
    (evaluation_id, ts, scope, tool, operation, pattern_key, features, hard_rule, model_action, audit)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const label = db.prepare("UPDATE decisions SET human_action = ?, human_ts = ? WHERE evaluation_id = ?");
  const list = db.prepare("SELECT * FROM decisions WHERE scope = ? ORDER BY ts");
  const labelled = db.prepare(`SELECT * FROM decisions
    WHERE tool = ? AND operation = ? AND human_action IS NOT NULL AND COALESCE(human_ts, ts) >= ?
      AND NOT (human_action = 'deny' AND COALESCE(human_ts, ts) - ts < ?)`);

  return {
    recordEvaluation(row) {
      insert.run(row.evaluationId, row.ts, row.scope, row.toolName, row.operation, row.patternKey,
        JSON.stringify(featuresFromHeads(row.heads)), row.hardRuleHit ? 1 : 0, row.modelAction,
        row.audit ? 1 : 0);
    },
    recordHumanDecision(evaluationId, action, ts) {
      return Number(label.run(action, ts, evaluationId).changes) > 0;
    },
    listDecisions(scope) {
      return (list.all(scope) as unknown as Row[]).map(toRecord);
    },
    listLabelled(toolName, operation, since) {
      return (labelled.all(toolName, operation, since, MIN_HUMAN_DENIAL_MS) as unknown as Row[]).map(toRecord);
    },
    columnNames() {
      return (db.prepare("PRAGMA table_info(decisions)").all() as { name: string }[]).map((c) => c.name);
    },
    close() {
      db.close();
    },
  };
}

function toRecord(r: Row): DecisionRecord {
  return {
        evaluationId: r.evaluation_id,
        ts: r.ts,
        scope: r.scope,
        toolName: r.tool,
        operation: r.operation,
        patternKey: r.pattern_key,
        features: JSON.parse(r.features) as number[],
        hardRuleHit: r.hard_rule === 1,
        modelAction: r.model_action as "allow" | "prompt",
        audit: r.audit === 1,
        humanAction: r.human_action as HumanAction | null,
        humanTs: r.human_ts,
  };
}
