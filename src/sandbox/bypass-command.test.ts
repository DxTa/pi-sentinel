import { describe, expect, it } from "vitest";

import { shouldBypassSandboxCommand } from "./bypass-command.js";

describe("shouldBypassSandboxCommand", () => {
  it.each([
    "git push origin main",
    "git fetch --all",
    "git pull --rebase",
    "git clone git@github.com:DxTa/pi-sentinel.git",
    "git ls-remote origin",
    "git submodule update --init --recursive",
  ])("bypasses host-level git transport command %s", (command) => {
    expect(shouldBypassSandboxCommand(command, [])).toBe(true);
  });

  it.each([
    "git status",
    "git diff --check",
    "git commit -m test",
    "echo git push origin main",
    "git push origin main && echo done",
  ])("keeps command sandboxed by default %s", (command) => {
    expect(shouldBypassSandboxCommand(command, [])).toBe(false);
  });
});
