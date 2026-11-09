import { describe, expect, it, vi } from "vitest";

import type { ConfigListEntry, ConfigListKind } from "./config-lists";
import { ConfigListView, type ListViewController, type ListViewDialogs } from "./config-list-view";

const ESC = "\u001b";
const TAB = "\t";

function fakeController(initial: Partial<Record<"session" | "project" | "global", ConfigListEntry[]>> = {}) {
  const store = { session: [], project: [], global: [], ...initial } as Record<
    "session" | "project" | "global",
    ConfigListEntry[]
  >;
  const edits: Array<{ kind: ConfigListKind; scope: string; value: string; state: string }> = [];
  const controller: ListViewController = {
    list: (_kind, scope) => store[scope],
    edit: (edit) => {
      edits.push(edit);
    },
  };
  return { controller, edits };
}

function fakeDialogs(answers: { input?: string; confirm?: boolean } = {}) {
  const dialogs: ListViewDialogs = {
    input: vi.fn(async () => answers.input),
    confirm: vi.fn(async () => answers.confirm ?? false),
  };
  return dialogs;
}

describe("ConfigListView", () => {
  it("shows the active scope and cycles it on Tab", () => {
    const { controller } = fakeController();
    const view = new ConfigListView("networkDomain", "Network domains", controller, fakeDialogs(), () => {});

    expect(view.render(80).join("\n")).toContain("[project]");
    view.handleInput(TAB);
    expect(view.render(80).join("\n")).toContain("[global]");
  });

  it("adds a domain to the selected file scope", async () => {
    const { controller, edits } = fakeController();
    const view = new ConfigListView(
      "networkDomain",
      "Network domains",
      controller,
      fakeDialogs({ input: " api.example.com " }),
      () => {},
    );

    view.handleInput("a");
    await view.settled();

    expect(edits).toEqual([
      { kind: "networkDomain", scope: "project", value: "api.example.com", state: "allow" },
    ]);
  });

  it("asks before removing and removes only on confirm", async () => {
    const { controller, edits } = fakeController({
      project: [{ value: "api.example.com", state: "allow" }],
    });
    const dialogs = fakeDialogs({ confirm: false });
    const view = new ConfigListView("networkDomain", "Network domains", controller, dialogs, () => {});

    view.handleInput("d");
    await view.settled();
    expect(dialogs.confirm).toHaveBeenCalledTimes(1);
    expect(edits).toEqual([]);
  });

  it("flips a deny row to allow with x", async () => {
    const { controller, edits } = fakeController({
      project: [{ value: "docs.example.com", state: "deny" }],
    });
    const view = new ConfigListView("networkDomain", "Network domains", controller, fakeDialogs(), () => {});

    view.handleInput("x");
    await view.settled();

    expect(edits).toEqual([
      { kind: "networkDomain", scope: "project", value: "docs.example.com", state: "allow" },
    ]);
  });

  it("never edits in the effective view and shows its rows read-only", async () => {
    const { controller, edits } = fakeController({
      global: [{ value: "docs.example.com", state: "deny" }],
    });
    const dialogs = fakeDialogs({ input: "x.example.com" });
    const view = new ConfigListView("networkDomain", "Network domains", controller, dialogs, () => {});

    view.handleInput(TAB);
    view.handleInput(TAB);
    view.handleInput("a");
    view.handleInput("d");
    await view.settled();

    expect(view.render(80).join("\n")).toContain("[effective]");
    expect(view.render(80).join("\n")).toContain("global");
    expect(dialogs.input).not.toHaveBeenCalled();
    expect(edits).toEqual([]);
  });

  it("closes on the kitty-protocol Escape sequence too", () => {
    const { controller } = fakeController();
    const onClose = vi.fn();
    const view = new ConfigListView("networkDomain", "Network domains", controller, fakeDialogs(), onClose);

    view.handleInput("\u001b[27u");

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes on Escape", () => {
    const { controller } = fakeController();
    const onClose = vi.fn();
    const view = new ConfigListView("networkDomain", "Network domains", controller, fakeDialogs(), onClose);

    view.handleInput(ESC);

    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
