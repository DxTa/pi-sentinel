import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

import { EXTENSION_ID } from "./extension-config";
import type { PermissionEventBus } from "./permission-events";

export const PROMPT_WAIT_STATUS_KEY = `${EXTENSION_ID}:prompt`;

export type PromptWaitToken = symbol;

type PromptStatusContext = {
  hasUI?: boolean;
  ui: Pick<ExtensionContext["ui"], "setStatus">;
};

type PromptEntry = {
  token: PromptWaitToken;
  message: string;
};

export class PromptWaitTracker {
  private readonly activeEntries: PromptEntry[] = [];

  constructor(
    private readonly events?: Pick<PermissionEventBus, "emit">,
    private readonly statusKey: string = PROMPT_WAIT_STATUS_KEY,
  ) {}

  begin(ctx: PromptStatusContext, message: string): PromptWaitToken | undefined {
    if ("hasUI" in ctx && ctx.hasUI !== true) {
      return undefined;
    }

    const token = Symbol("prompt-wait");
    this.activeEntries.push({ token, message });
    ctx.ui.setStatus(this.statusKey, message);
    this.events?.emit("herdr:blocked", { active: true, label: message });
    return token;
  }

  end(ctx: PromptStatusContext, token: PromptWaitToken | undefined): void {
    if (!token) {
      return;
    }

    const index = this.activeEntries.findIndex((entry) => entry.token === token);
    if (index < 0) {
      return;
    }

    const [removed] = this.activeEntries.splice(index, 1);
    const next = this.activeEntries.at(-1);
    ctx.ui.setStatus(this.statusKey, next?.message);
    this.events?.emit("herdr:blocked", { active: false, label: removed.message });
  }

  clear(ctx?: PromptStatusContext): void {
    for (const entry of this.activeEntries) {
      this.events?.emit("herdr:blocked", {
        active: false,
        label: entry.message,
      });
    }
    this.activeEntries.length = 0;
    ctx?.ui.setStatus(this.statusKey, undefined);
  }
}
