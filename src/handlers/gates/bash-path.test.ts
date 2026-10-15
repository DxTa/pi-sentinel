import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { describe, expect, it } from "vitest";

import { describeBashPathGate } from "./bash-path";
import type { PermissionCheckResult } from "#src/types";
import type { ToolCallContext } from "./types";

function bashContext(command: string, cwd: string, sandboxed = true): ToolCallContext {
  return {
    toolName: "bash",
    input: { command },
    agentName: null,
    toolCallId: "tool-1",
    cwd,
    sandboxed,
  };
}

function pathDecision(
  state: PermissionCheckResult["state"],
  matchedPattern: string,
): PermissionCheckResult {
  return {
    toolName: "path",
    state,
    matchedPattern,
    source: "tool",
    origin: "project",
  };
}

describe("describeBashPathGate dotenv reads", () => {
  it("bypasses a dotenv deny for a read-only workspace dotenv read", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-bash-env-path-"));
    const envPath = join(workspace, ".env.local");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    const denyDotenv = (_surface: string, input: unknown) => {
      const requestedPath = (input as { path: string }).path;
      return basename(requestedPath).toLowerCase() === ".env.local"
        ? pathDecision("deny", "*.env.*")
        : pathDecision("allow", "*");
    };

    try {
      const result = await describeBashPathGate(
        bashContext(`cat ${envPath}`, workspace),
        denyDotenv,
        () => [],
        [envPath],
      );
      expect(result).toBeNull();
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it.each([
    ["ask", "*.env.*", `cat .env.local`],
    ["deny", "*", `cat .env.local`],
    ["deny", "*.env.*", `cat .env.local > copy.txt`],
  ] as const)("keeps %s %s policy for %s", async (state, pattern, command) => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-bash-env-path-"));
    const envPath = join(workspace, ".env.local");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    const check = (surface: string, input: unknown) => {
      if (surface !== "path") return pathDecision("allow", "*");
      const requestedPath = (input as { path: string }).path;
      return basename(requestedPath).toLowerCase() === ".env.local"
        ? pathDecision(state, pattern)
        : pathDecision("allow", "*");
    };

    try {
      const result = await describeBashPathGate(
        bashContext(command.replace(".env.local", envPath), workspace),
        check,
        () => [],
        [envPath],
      );
      expect(result).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("does not bypass a dotenv deny when a command also touches another path", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-bash-env-path-"));
    const envPath = join(workspace, ".env.local");
    const pemPath = join(workspace, "client.pem");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    writeFileSync(pemPath, "private-key");
    const check = (_surface: string, input: unknown) => {
      const requestedPath = (input as { path: string }).path;
      return basename(requestedPath) === ".env.local"
        ? pathDecision("deny", "*.env.*")
        : pathDecision("deny", "*.pem");
    };

    try {
      const result = await describeBashPathGate(
        bashContext(`cat ${envPath} ${pemPath}`, workspace),
        check,
        () => [],
        [envPath, pemPath],
      );
      expect(result).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("keeps dotenv denies when Bash is not sandboxed", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-bash-env-path-"));
    const envPath = join(workspace, ".env.local");
    writeFileSync(envPath, "TOKEN=secret-value\n");

    try {
      const result = await describeBashPathGate(
        bashContext(`cat ${envPath}`, workspace, false),
        () => pathDecision("deny", "*.env.*"),
        () => [],
        [envPath],
      );
      expect(result).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("does not bypass dotenv denies for external files", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-bash-env-path-"));
    const outside = mkdtempSync(join(tmpdir(), "pi-bash-env-outside-"));
    const envPath = join(outside, ".env.local");
    writeFileSync(envPath, "TOKEN=secret-value\n");

    try {
      const result = await describeBashPathGate(
        bashContext(`cat ${envPath}`, workspace),
        () => pathDecision("deny", "*.env.*"),
        () => [],
        [envPath],
      );
      expect(result).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });
});
