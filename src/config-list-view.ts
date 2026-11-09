import { getKeybindings, matchesKey } from "@earendil-works/pi-tui";

import type { ConfigListEntry, ConfigListKind, ConfigListScope } from "./config-lists";
import {
  effectiveRows,
  flipState,
  keyAction,
  nextViewScope,
  type ListViewRow,
  type ListViewScope,
} from "./config-list-model";

export interface ListViewController {
  list(kind: ConfigListKind, scope: ConfigListScope): ConfigListEntry[];
  edit(edit: {
    kind: ConfigListKind;
    scope: ConfigListScope;
    value: string;
    state: string;
    surface?: string;
  }): void;
}

export interface ListViewDialogs {
  input(title: string, placeholder: string): Promise<string | undefined>;
  confirm(title: string): Promise<boolean>;
}

const SCOPES: ListViewScope[] = ["session", "project", "global", "effective"];
const VIM_UP = "k";
const VIM_DOWN = "j";

const PLACEHOLDER: Record<ConfigListKind, string> = {
  networkDomain: "domain, e.g. api.example.com",
  permissionRule: "surface and pattern, e.g. bash git push *",
  sandboxPath: "absolute path",
  hostFallback: "command prefix, e.g. docker compose",
  yoloAskPattern: "command pattern, e.g. make deploy-*",
};

/** Initial state for a new entry of each kind. */
const DEFAULT_STATE: Record<ConfigListKind, string> = {
  networkDomain: "allow",
  permissionRule: "allow",
  sandboxPath: "ro",
  hostFallback: "on",
  yoloAskPattern: "on",
};

/** Parse the add input. Permission rules take "surface pattern"; other kinds take one value. */
function parseEntry(kind: ConfigListKind, input: string): { value: string; surface?: string } | undefined {
  const text = input.trim();
  if (!text) return undefined;
  if (kind !== "permissionRule") return { value: text };
  const space = text.indexOf(" ");
  if (space < 0) return undefined;
  return { surface: text.slice(0, space), value: text.slice(space + 1).trim() };
}

/**
 * Interactive list of one entry kind across session, project, global, and an
 * effective read-only view. Keys: Tab scope, a add, e edit, d remove, x flip, Esc close.
 */
export class ConfigListView {
  private scope: ListViewScope = "project";
  private selected = 0;
  private status = "";
  private pending: Promise<void> = Promise.resolve();

  constructor(
    private readonly kind: ConfigListKind,
    private readonly title: string,
    private readonly controller: ListViewController,
    private readonly dialogs: ListViewDialogs,
    private readonly onClose: () => void,
  ) {}

  /** Resolves when the last dialog-driven change has finished. */
  settled(): Promise<void> {
    return this.pending;
  }

  rows(): ListViewRow[] {
    const scope = this.scope;
    if (scope === "effective") {
      return effectiveRows({
        session: this.controller.list(this.kind, "session"),
        project: this.controller.list(this.kind, "project"),
        global: this.controller.list(this.kind, "global"),
      });
    }
    return this.controller.list(this.kind, scope).map((entry) => ({
      value: entry.value,
      state: entry.state,
      ...(entry.surface !== undefined ? { surface: entry.surface } : {}),
      source: scope,
      editable: true,
    }));
  }

  render(width: number): string[] {
    const tabs = SCOPES.map((scope) => (scope === this.scope ? `[${scope}]` : scope)).join("  ");
    const rows = this.rows();
    const lines = [this.title, tabs, ""];
    if (rows.length === 0) lines.push("  (none)");
    rows.forEach((row, index) => {
      const cursor = index === this.selected ? "▶" : " ";
      const surface = row.surface ? `${row.surface} ` : "";
      const origin = row.editable ? "" : `  (from ${row.source})`;
      lines.push(`${cursor} ${surface}${row.value}  ${row.state}${origin}`.slice(0, width));
    });
    lines.push("", "Tab scope · a add · e edit · d remove · x flip · Esc close");
    if (this.status) lines.push(this.status);
    return lines;
  }

  invalidate(): void {
    // Rendered from current config on every call; nothing cached.
  }

  handleInput(data: string): void {
    const kb = getKeybindings();
    if (kb.matches(data, "tui.select.cancel")) {
      this.onClose();
      return;
    }
    if (kb.matches(data, "tui.select.up") || data === VIM_UP) {
      this.selected = Math.max(0, this.selected - 1);
      return;
    }
    if (kb.matches(data, "tui.select.down") || data === VIM_DOWN) {
      this.selected = Math.min(Math.max(0, this.rows().length - 1), this.selected + 1);
      return;
    }
    const key = matchesKey(data, "tab") ? "\t" : data;
    const action = keyAction(key, this.scope, this.kind);
    if (action === "next-scope") {
      this.scope = nextViewScope(this.scope);
      this.selected = 0;
      return;
    }
    if (action === "add") this.run(() => this.add());
    else if (action === "edit") this.run(() => this.edit());
    else if (action === "remove") this.run(() => this.remove());
    else if (action === "flip") this.run(() => this.flip());
  }

  private run(operation: () => Promise<void>): void {
    this.pending = operation().catch((error: unknown) => {
      this.status = `Error: ${error instanceof Error ? error.message : String(error)}`;
    });
  }

  private writableScope(): ConfigListScope {
    return this.scope as ConfigListScope;
  }

  private async add(): Promise<void> {
    const scope = this.writableScope();
    const input = await this.dialogs.input(`Add to ${scope}`, PLACEHOLDER[this.kind]);
    const entry = input === undefined ? undefined : parseEntry(this.kind, input);
    if (!entry) return;
    this.controller.edit({ kind: this.kind, scope, value: entry.value, state: DEFAULT_STATE[this.kind], surface: entry.surface });
    this.status = `Added ${entry.value} to ${scope}.`;
  }

  private selectedEditable(): ListViewRow | undefined {
    const row = this.rows()[this.selected];
    if (!row || !row.editable) return undefined;
    return row;
  }

  private async edit(): Promise<void> {
    const row = this.selectedEditable();
    if (!row) return;
    const scope = this.writableScope();
    const input = await this.dialogs.input(`Edit in ${scope}`, row.value);
    const entry = input === undefined ? undefined : parseEntry(this.kind, input);
    if (!entry || (entry.value === row.value && entry.surface === row.surface)) return;
    this.controller.edit({ kind: this.kind, scope, value: row.value, state: "remove", surface: row.surface });
    this.controller.edit({ kind: this.kind, scope, value: entry.value, state: row.state, surface: entry.surface ?? row.surface });
    this.status = `Edited to ${entry.value}.`;
  }

  private async remove(): Promise<void> {
    const row = this.selectedEditable();
    if (!row) return;
    const scope = this.writableScope();
    const ok = await this.dialogs.confirm(`Remove ${row.value} from ${scope}?`);
    if (!ok) return;
    this.controller.edit({ kind: this.kind, scope, value: row.value, state: "remove", surface: row.surface });
    this.status = `Removed ${row.value} from ${scope}.`;
  }

  private async flip(): Promise<void> {
    const row = this.selectedEditable();
    if (!row) return;
    const scope = this.writableScope();
    const state = flipState(row.state);
    if (state === row.state) return;
    this.controller.edit({ kind: this.kind, scope, value: row.value, state, surface: row.surface });
    this.status = `${row.value} is now ${state}.`;
  }
}
