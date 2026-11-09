import { describe, expect, it } from "vitest";

import {
  effectiveRows,
  flipState,
  keyAction,
  nextViewScope,
  type ListViewRow,
} from "./config-list-model";

describe("list view scope cycle", () => {
  it("cycles session, project, global, effective, then back to session on Tab", () => {
    expect(nextViewScope("session")).toBe("project");
    expect(nextViewScope("project")).toBe("global");
    expect(nextViewScope("global")).toBe("effective");
    expect(nextViewScope("effective")).toBe("session");
  });
});

describe("key actions", () => {
  it("maps a, d, x, e to edits in a writable scope", () => {
    expect(keyAction("a", "project", "networkDomain")).toBe("add");
    expect(keyAction("d", "global", "networkDomain")).toBe("remove");
    expect(keyAction("x", "session", "networkDomain")).toBe("flip");
    expect(keyAction("e", "project", "permissionRule")).toBe("edit");
  });

  it("blocks edits in the read-only effective view", () => {
    expect(keyAction("a", "effective", "networkDomain")).toBe("none");
    expect(keyAction("d", "effective", "networkDomain")).toBe("none");
  });

  it("flips only kinds that have an opposite state", () => {
    expect(keyAction("x", "project", "yoloAskPattern")).toBe("none");
    expect(keyAction("x", "project", "sandboxPath")).toBe("flip");
  });

  it("always handles Tab as a scope change", () => {
    expect(keyAction("\t", "effective", "yoloAskPattern")).toBe("next-scope");
  });
});

describe("flipState", () => {
  it("swaps allow and deny, and ro and rw", () => {
    expect(flipState("allow")).toBe("deny");
    expect(flipState("deny")).toBe("allow");
    expect(flipState("ro")).toBe("rw");
    expect(flipState("rw")).toBe("ro");
  });
});

describe("effective rows", () => {
  it("shows each entry once with the highest-precedence source that sets it", () => {
    const rows: ListViewRow[] = effectiveRows({
      session: [{ surface: "bash", value: "git push *", state: "allow" }],
      project: [
        { surface: "bash", value: "git push *", state: "deny" },
        { surface: "read", value: "*", state: "allow" },
      ],
      global: [{ surface: "read", value: "*", state: "deny" }],
    });

    expect(rows).toEqual([
      { surface: "bash", value: "git push *", state: "allow", source: "session", editable: false },
      { surface: "read", value: "*", state: "allow", source: "project", editable: false },
    ]);
  });
});
