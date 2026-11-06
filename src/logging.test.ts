import { chmodSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createPermissionSystemLogger } from "./logging";
import { redactSecrets } from "./secret-redaction";

function loggerFixture(debugLog: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "pi-sentinel-logging-"));
  const debugLogPath = join(dir, "debug.jsonl");
  const reviewLogPath = join(dir, "review.jsonl");
  const config = {
    debugLog,
    permissionReviewLog: true,
    mode: "manual" as const,
    yoloAskBashPatterns: [],
  };
  return {
    config,
    debugLogPath,
    reviewLogPath,
    logger: createPermissionSystemLogger({
      getConfig: () => config,
      debugLogPath,
      reviewLogPath,
      ensureLogsDirectory: () => undefined,
    }),
  };
}

describe("createPermissionSystemLogger", () => {
  it("redacts known credentials", () => {
    const token = "ghp_" + "a".repeat(36);

    expect(redactSecrets(token)).toBe("[REDACTED: GitHub Token]");
  });

  it("does not write debug records when debug logging is disabled", () => {
    const { logger, debugLogPath } = loggerFixture(false);

    logger.debug("tool_call.received", { toolName: "read" });

    expect(existsSync(debugLogPath)).toBe(false);
  });

  it("adds permission mode context to bounded debug records", () => {
    const { logger, debugLogPath } = loggerFixture(true);

    logger.debug("tool_call.received", {
      toolCallId: "tool-1",
      toolName: "write",
      toolInputPreview: "for 'notes.txt' (1 line, 3 characters)",
    });

    const record = JSON.parse(readFileSync(debugLogPath, "utf8")) as Record<string, unknown>;
    expect(record).toMatchObject({
      stream: "debug",
      event: "tool_call.received",
      mode: "manual",
      toolCallId: "tool-1",
      toolName: "write",
    });
    expect(JSON.stringify(record)).not.toContain("secret-value");
  });

  it("redacts sensitive assignments and known credentials in debug and review logs", () => {
    const { logger, debugLogPath, reviewLogPath } = loggerFixture(true);
    const token = "ghp_" + "a".repeat(36);
    const command = "BRIDGE_POSTGRES_PASSWORD=admin " + token + " docker ps";

    logger.debug("permission_request.waiting", { command });
    logger.review("permission_request.waiting", { command });

    for (const path of [debugLogPath, reviewLogPath]) {
      const log = readFileSync(path, "utf8");
      expect(log).toContain("BRIDGE_POSTGRES_PASSWORD=[REDACTED]");
      expect(log).toContain("[REDACTED: GitHub Token]");
      expect(log).not.toContain("=admin");
      expect(log).not.toContain(token);
    }
  });

  it("records the permission mode on every review entry", () => {
    const { logger, config, reviewLogPath } = loggerFixture(false);
    logger.review("first", {});
    (config as { mode: string }).mode = "yolo";
    logger.review("second", {});

    const modes = readFileSync(reviewLogPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).mode);
    expect(modes).toEqual(["manual", "yolo"]);
  });

  it("creates logs with mode 0600 and tightens existing log permissions", () => {
    const { logger, debugLogPath, reviewLogPath } = loggerFixture(true);
    writeFileSync(reviewLogPath, "old record\n", "utf8");
    chmodSync(reviewLogPath, 0o644);

    logger.debug("debug", { ok: true });
    logger.review("review", { ok: true });

    expect(statSync(debugLogPath).mode & 0o777).toBe(0o600);
    expect(statSync(reviewLogPath).mode & 0o777).toBe(0o600);
  });
});
