import { describe, expect, it } from "vitest";

import { isDockerCommand, shouldBypassSandboxCommand } from "./bypass-command.js";

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

  it.each([
    ["uv venv .venv", ["uv *"]],
    ["python -m venv .venv", ["python -m venv *"]],
    ["npm install -g typescript", ["npm install -g *"]],
    ["cargo install ripgrep", ["cargo install *"]],
    ["go install golang.org/x/tools/gopls@latest", ["go install *"]],
  ])("allows explicitly configured host environment command %s", (command, patterns) => {
    expect(shouldBypassSandboxCommand(command, patterns)).toBe(true);
  });

  it("does not let an explicit host pattern bypass a compound shell command", () => {
    expect(shouldBypassSandboxCommand("uv venv .venv " + String.fromCharCode(38) + " echo done", ["uv *"])).toBe(false);
    expect(shouldBypassSandboxCommand("uv venv .venv && uv run pytest", ["uv *"])).toBe(false);
  });

  it("allows every command when the explicit wildcard host pattern is configured", () => {
    expect(shouldBypassSandboxCommand("uv venv .venv && uv run pytest", ["*"])).toBe(true);
  });
});


describe("isDockerCommand", () => {
  it.each([
    "docker ps",
    "docker compose up",
    "docker buildx ls",
    "docker-compose config",
    "/usr/local/bin/docker info",
  ])("recognizes direct Docker command %s", (command) => {
    expect(isDockerCommand(command)).toBe(true);
  });

  it.each([
    "docker ps && echo done",
    "echo docker ps",
    "sudo docker ps",
    "sh -c 'docker ps'",
    "docker ps | cat",
  ])("rejects compound or indirect command %s", (command) => {
    expect(isDockerCommand(command)).toBe(false);
  });
});
