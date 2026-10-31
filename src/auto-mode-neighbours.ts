/**
 * Summarise past human decisions for the same request shape (D16).
 * Only the same tool/operation/pattern key counts: head features barely vary
 * across paths for one tool, so feature similarity let a single denial block
 * unrelated requests. Hard-rule rows are excluded; the hard rule owns those.
 */
import type { DecisionRecord } from "./auto-mode-decision-store";

export const NEIGHBOUR_WINDOW_MS = 30 * 86_400_000;
export const APPROVAL_HALF_LIFE_MS = 14 * 86_400_000;
const DAY_MS = 86_400_000;

export interface NeighbourQuery {
  scope: string;
  toolName: string;
  operation: string;
  patternKey: string;
  features: number[];
  now: number;
}

/**
 * Approvals count only explicit, non-audit answers. `approvalWeight` halves every
 * 14 days. A scope is "denied" while its latest explicit decision is a denial.
 */
export interface NeighbourSummary {
  workspace: {
    approvals: number;
    approvalWeight: number;
    approvalDays: number;
    denials: number;
    latestIsDeny: boolean;
  };
  global: {
    approvals: number;
    approvalWeight: number;
    approvalDays: number;
    /** Distinct other workspaces with a counted approval. */
    workspaces: number;
    denials: number;
    /** Other workspaces whose latest decision is a denial. */
    denialWorkspaces: number;
  };
}

interface Evidence {
  approvals: number;
  approvalWeight: number;
  days: Set<number>;
  denials: number;
}

const emptyEvidence = (): Evidence => ({ approvals: 0, approvalWeight: 0, days: new Set(), denials: 0 });

function addApproval(bucket: Evidence, at: number, now: number): void {
  bucket.approvals += 1;
  bucket.approvalWeight += 0.5 ** ((now - at) / APPROVAL_HALF_LIFE_MS);
  bucket.days.add(Math.floor(at / DAY_MS));
}

function noteLatest(latest: Map<string, { at: number; deny: boolean }>, scope: string, at: number, deny: boolean): void {
  const previous = latest.get(scope);
  if (!previous || at > previous.at || (at === previous.at && deny)) latest.set(scope, { at, deny });
}

const sameKey = (r: DecisionRecord, q: NeighbourQuery): boolean =>
  r.toolName === q.toolName && r.operation === q.operation && r.patternKey === q.patternKey;

export function summarizeNeighbours(
  records: readonly DecisionRecord[],
  query: NeighbourQuery,
): NeighbourSummary {
  const workspace = emptyEvidence();
  const global = emptyEvidence();
  const approvingScopes = new Set<string>();
  const latest = new Map<string, { at: number; deny: boolean }>();
  for (const r of records) {
    const at = r.humanTs ?? r.ts;
    if (r.humanAction === null || r.hardRuleHit || !sameKey(r, query) || query.now - at > NEIGHBOUR_WINDOW_MS) continue;
    const deny = r.humanAction === "deny";
    noteLatest(latest, r.scope, at, deny);
    const bucket = r.scope === query.scope ? workspace : global;
    if (deny) {
      bucket.denials += 1;
    } else if (!r.audit) {
      addApproval(bucket, at, query.now);
      if (bucket === global) approvingScopes.add(r.scope);
    }
  }
  const denialWorkspaces = [...latest].filter(([scope, d]) => scope !== query.scope && d.deny).length;
  return {
    workspace: {
      approvals: workspace.approvals,
      approvalWeight: workspace.approvalWeight,
      approvalDays: workspace.days.size,
      denials: workspace.denials,
      latestIsDeny: latest.get(query.scope)?.deny ?? false,
    },
    global: {
      approvals: global.approvals,
      approvalWeight: global.approvalWeight,
      approvalDays: global.days.size,
      workspaces: approvingScopes.size,
      denials: global.denials,
      denialWorkspaces,
    },
  };
}
