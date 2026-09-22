import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createPermissionSystemLogger } from "./logging";

function loggerFixture(debugLog: boolean) {
  const dir = mkdtempSync(join("/tmp", "pi-sentinel-logging-"));
  const debugLogPath = join(dir, "debug.jsonl");
  const reviewLogPath = join(dir, "review.jsonl");
  const config = {
    debugLog,
    permissionReviewLog: true,
    mode: "manual" as const,
    yoloAutoMaxLevel: "l2" as const,
    yoloAskBashPatterns: [],
  };
  return {
    config,
    debugLogPath,
    logger: createPermissionSystemLogger({
      getConfig: () => config,
      debugLogPath,
      reviewLogPath,
      ensureLogsDirectory: () => undefined,
    }),
  };
}

describe("createPermissionSystemLogger", () => {
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
      yoloAutoMaxLevel: "l2",
      toolCallId: "tool-1",
      toolName: "write",
    });
    expect(JSON.stringify(record)).not.toContain("secret-value");
  });
});
