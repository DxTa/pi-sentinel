import { describe, expect, it } from "vitest";

import {
  isHostFallbackGranted,
  isDockerCommand,
  hasDockerEndpointOverride,
  isDockerDaemonCommand,
  isHostCapabilityBootstrapCommand,
  shouldBypassSandboxCommand,
} from "./bypass-command.js";

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


describe("isDockerDaemonCommand", () => {
  it.each([
    "docker ps",
    "docker ps --format 'table {{.Names}}\\t{{.Status}}'",
    "docker version",
    "d'o'cker ps",
    "docker ps && echo done",
    "docker ps | head",
    "docker ps > /tmp/list",
    "docker ps 2>&1",
    "docker ps &> /tmp/out",
    ">& /tmp/out docker ps",
    ">/dev/null< /dev/null docker ps",
    ">| out docker ps",
    "{fd}>out docker ps",
    "0<&0 docker ps",
    "docker ps\necho done",
    "> /tmp/list docker ps",
    "docker ps --help",
    "docker exec app mytool --help",
    "docker run --rm alpine echo --help",
    "/usr/local/bin/docker info",
  ])("recognizes Docker daemon command %s", (command) => {
    expect(isDockerDaemonCommand(command)).toBe(true);
  });

  it.each([
    "docker --help",
    'docker "--help"',
    "env DOCKER_HOST=unix:///tmp/docker.sock docker --help",
    "docker --version",
    "docker -h",
    "docker -v",
    "/usr/local/bin/docker --version",
    "docker help ps",
    "docker --help && echo done",
    "docker -h | cat",
    "docker --help > /tmp/help",
  ])("rejects Docker client-only or compound command %s", (command) => {
    expect(isDockerDaemonCommand(command)).toBe(false);
  });
});


describe("hasDockerEndpointOverride", () => {
  it.each([
    "DOCKER_HOST=tcp://example.invalid docker ps",
    "DOCKER_CONFIG=/tmp/docker-config docker ps",
    "env DOCKER_HOST=tcp://example.invalid docker ps",
    "sudo env DOCKER_HOST=tcp://example.invalid docker ps",
    "docker --host tcp://example.invalid ps",
    "docker --\\host tcp://example.invalid ps",
    "docker --context production ps",
    "docker --config /tmp/docker-config ps",
    `docker --config "$CONFIG_DIR" ps`,
    "bash -c 'DOCKER_HOST=tcp://example.invalid docker ps'",
    "bash -c 'docker --host tcp://example.invalid ps'",
    `bash <<< 'docker --host tcp://example.invalid ps'`,
    `bash <<< 'docker "$OPTIONS" ps'`,
    `bash <<< 'export DOCKER_HOST=tcp://example.invalid; docker ps'`,
    `bash <<< 'unset DOCKER_HOST; docker ps'`,
    `bash <<< 'source ./docker-env; docker ps'`,
    `bash <<< 'V=DOCKER_HOST; export "$V=tcp://example.invalid"; docker ps'`,
    `bash -c 'docker "$@" ps' -- --host tcp://example.invalid`,
    `bash -c 'docker "$OPTIONS" ps'`,
    `echo "$(DOCKER_HOST=tcp://example.invalid docker ps)"`,
    `echo "$(docker --host tcp://example.invalid ps)"`,
    `echo "$(docker "$OPTIONS" ps)"`,
    "DOCKER_HOST=tcp://example.invalid; docker ps",
    "export DOCKER_HOST=tcp://example.invalid; docker ps",
    "export DOCKER_CONFIG=/tmp/docker-config; docker ps",
    "export 'DOCKER_CONTEXT=production'; docker ps",
    "unset DOCKER_HOST; docker ps",
    "env -u DOCKER_HOST docker ps",
    "env -u DOCKER_CONFIG docker ps",
    "env --unset=DOCKER_CONTEXT docker ps",
    "env -i docker ps",
    "env --ignore-environment -S 'docker ps'",
    "env -S '-i docker ps'",
    "env -i -S 'docker ps'",
    "X=1 DOCKER_HOST=tcp://example.invalid; docker ps",
    "bash -c 'export DOCKER_CONTEXT=production; docker ps'",
  ])("detects command-level Docker host overrides in %s", (command) => {
    expect(hasDockerEndpointOverride(command)).toBe(true);
  });

  it.each([
    "docker ps",
    "TRACE=1 docker ps",
    "docker run --env DOCKER_HOST=tcp://example.invalid image",
    "docker run image mytool --config /app/config",
    "docker ps --format 'docker --host foo'",
    "echo DOCKER_HOST=tcp://example.invalid",
    `bash -c 'docker ps'`,
    `bash -c 'docker ps "$FORMAT"'`,
  ])("does not classify unrelated variables as Docker host overrides in %s", (command) => {
    expect(hasDockerEndpointOverride(command)).toBe(false);
  });
});

describe("isHostCapabilityBootstrapCommand", () => {
  it.each([
    "pkgx install ruff",
    "/opt/pkgx/pkgx install ruff",
    "python -m venv .venv",
    "python3 -m venv .venv",
    "python3.14 -m venv .venv",
    "/usr/bin/python3 -m venv .venv",
  ])("recognizes direct host-capability command %s", (command) => {
    expect(isHostCapabilityBootstrapCommand(command)).toBe(true);
  });

  it.each([
    "echo pkgx install ruff",
    "sh -c 'python -m venv .venv'",
    "python -m pip install venv",
    "pkgx install ruff && echo done",
    "python -m venv .venv | cat",
  ])("rejects indirect or unrelated command %s", (command) => {
    expect(isHostCapabilityBootstrapCommand(command)).toBe(false);
  });
});

describe("isHostFallbackGranted", () => {
  const grants = ["docker build"];

  it("grants a plain granted prefix", () => {
    expect(isHostFallbackGranted("docker build -t beaver:local .", grants)).toBe(true);
  });

  it.each([
    "sudo -n docker build .",
    "HOME=/tmp/h docker build .",
    "bash -c 'docker build .'",
    "docker build . ; cat ~/.ssh/id_rsa",
    "docker build . > ~/.zshrc",
  ])("rejects %s", (command) => {
    expect(isHostFallbackGranted(command, grants)).toBe(false);
  });
});
