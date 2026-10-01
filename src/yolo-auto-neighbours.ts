/**
 * Summarise past human decisions for the same request shape (D16).
 * Only the same tool/operation/pattern key counts: head features barely vary
 * across paths for one tool, so feature similarity let a single denial block
 * unrelated requests. Hard-rule rows are excluded; the hard rule owns those.
 */
import type { DecisionRecord } from "./yolo-auto-decision-store";

export const NEIGHBOUR_WINDOW_MS = 30 * 86_400_000;

export interface NeighbourQuery {
  scope: string;
  toolName: string;
  operation: string;
  patternKey: string;
  features: number[];
  now: number;
}

export interface NeighbourSummary {
  workspace: { approvals: number; denials: number };
  global: { approvals: number; denials: number; workspaces: number };
}

export function summarizeNeighbours(
  records: readonly DecisionRecord[],
  query: NeighbourQuery,
): NeighbourSummary {
  const summary: NeighbourSummary = {
    workspace: { approvals: 0, denials: 0 },
    global: { approvals: 0, denials: 0, workspaces: 0 },
  };
  const otherScopes = new Set<string>();
  for (const r of records) {
    if (r.humanAction === null || r.hardRuleHit) continue;
    if (r.toolName !== query.toolName || r.operation !== query.operation || r.patternKey !== query.patternKey) continue;
    if (query.now - (r.humanTs ?? r.ts) > NEIGHBOUR_WINDOW_MS) continue;
    const bucket = r.scope === query.scope ? summary.workspace : summary.global;
    if (r.humanAction === "deny") bucket.denials += 1;
    else bucket.approvals += 1;
    if (r.scope !== query.scope) otherScopes.add(r.scope);
  }
  summary.global.workspaces = otherScopes.size;
  return summary;
}
