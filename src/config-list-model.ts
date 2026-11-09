import type { ConfigListEntry, ConfigListKind } from "./config-lists";

export type ListViewScope = "session" | "project" | "global" | "effective";
export type ListViewAction = "add" | "remove" | "flip" | "edit" | "next-scope" | "none";

export interface ListViewRow {
  value: string;
  state: string;
  surface?: string;
  /** Highest-precedence scope that sets this entry. */
  source: Exclude<ListViewScope, "effective">;
  editable: boolean;
}

const SCOPE_ORDER: ListViewScope[] = ["session", "project", "global", "effective"];
const PRECEDENCE: Array<Exclude<ListViewScope, "effective">> = ["session", "project", "global"];
const FLIPPABLE: ReadonlySet<ConfigListKind> = new Set(["networkDomain", "permissionRule", "sandboxPath"]);

export function nextViewScope(scope: ListViewScope): ListViewScope {
  return SCOPE_ORDER[(SCOPE_ORDER.indexOf(scope) + 1) % SCOPE_ORDER.length];
}

/** Map a key to a list action; the effective view is read-only. */
export function keyAction(key: string, scope: ListViewScope, kind: ConfigListKind): ListViewAction {
  if (key === "\t") return "next-scope";
  if (scope === "effective") return "none";
  if (key === "a") return "add";
  if (key === "d") return "remove";
  if (key === "e") return "edit";
  if (key === "x") return FLIPPABLE.has(kind) ? "flip" : "none";
  return "none";
}

/** Opposite decision for `x`: allow and deny swap, ro and rw swap. Other states are unchanged. */
export function flipState(state: string): string {
  const opposites: Record<string, string> = { allow: "deny", deny: "allow", ro: "rw", rw: "ro" };
  return opposites[state] ?? state;
}

/** One row per entry, labelled with the scope that wins. Rows are never editable here. */
export function effectiveRows(
  bySource: Record<Exclude<ListViewScope, "effective">, ConfigListEntry[]>,
): ListViewRow[] {
  const seen = new Map<string, ListViewRow>();
  for (const source of PRECEDENCE) {
    for (const entry of bySource[source]) {
      const key = `${entry.surface ?? ""}\u0000${entry.value}`;
      if (seen.has(key)) continue;
      seen.set(key, {
        value: entry.value,
        state: entry.state,
        ...(entry.surface !== undefined ? { surface: entry.surface } : {}),
        source,
        editable: false,
      });
    }
  }
  return [...seen.values()];
}
