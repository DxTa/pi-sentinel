import { describe, expect, it, vi } from "vitest";

import { buildListSettingItems } from "./config-modal";

function deps() {
  return {
    controller: {
      list: vi.fn(() => [{ value: "api.example.com", state: "allow" }]),
      edit: vi.fn(),
    },
    dialogs: {
      input: vi.fn(async () => undefined),
      confirm: vi.fn(async () => false),
    },
  };
}

describe("list rows in the /sentinel menu", () => {
  it("adds one row per list kind", () => {
    const items = buildListSettingItems(deps());

    expect(items.map((item) => item.id)).toEqual([
      "list-network-domains",
      "list-permission-rules",
      "list-sandbox-paths",
      "list-yolo-ask-patterns",
      "list-host-fallback",
    ]);
  });

  it("opens the list view from the row and closes it with done", () => {
    const items = buildListSettingItems(deps());
    const done = vi.fn();
    const networkRow = items.find((item) => item.id === "list-network-domains");

    const view = networkRow?.submenu?.("", done) as { render(width: number): string[]; handleInput(data: string): void };
    expect(view.render(80).join("\n")).toContain("Network domains");

    view.handleInput("\u001b");
    expect(done).toHaveBeenCalledTimes(1);
  });
});
