import { mkdtempSync, readFileSync, rmSync, statSync, truncateSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { AutoModeCalibrationRecord } from "./auto-mode-evaluator";
import { writeAutoModeCalibrationRecord } from "./auto-mode-calibration";

const roots: string[] = [];
const tempDir = () => {
  const root = mkdtempSync(join(tmpdir(), "pi-yolo-calibration-"));
  roots.push(root);
  return root;
};
const record = (evaluationId: string): AutoModeCalibrationRecord => ({
  evaluationId,
  ts: "2026-09-29T00:00:00.000Z",
  modelRev: "model-r1",
  toolName: "read",
  operation: "read",
  textLength: 27,
  textSha256: "safe-hash",
  truncated: false,
  heads: null,
  decision: "prompt",
  reason: "worker_unavailable",
  hardRuleHit: false,
  audit: false,
  latencyMs: 12,
});

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("writeAutoModeCalibrationRecord", () => {
  it("appends JSONL records to an owner-only calibration log", async () => {
    const agentDir = tempDir();
    const first = record("evaluation-1");
    const second = record("evaluation-2");

    await writeAutoModeCalibrationRecord(agentDir, first);
    await writeAutoModeCalibrationRecord(agentDir, second);

    const logPath = join(agentDir, "logs", "auto-mode-calibration.jsonl");
    expect(readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line)))
      .toEqual([first, second]);
    expect(statSync(logPath).mode & 0o777).toBe(0o600);
    expect(statSync(join(agentDir, "logs")).mode & 0o777).toBe(0o700);
    expect(statSync(join(agentDir, "logs", ".auto-mode-calibration.lock")).mode & 0o777).toBe(0o600);
  });

  it("rotates at 50 MB and retains only the newest backup", async () => {
    const agentDir = tempDir();
    const logPath = join(agentDir, "logs", "auto-mode-calibration.jsonl");
    const rotatedPath = logPath + ".1";
    const limit = 50 * 1024 * 1024;

    await writeAutoModeCalibrationRecord(agentDir, record("evaluation-1"));
    truncateSync(logPath, limit);
    await writeAutoModeCalibrationRecord(agentDir, record("evaluation-2"));
    expect(readFileSync(rotatedPath, "utf8")).toContain("evaluation-1");

    await writeAutoModeCalibrationRecord(agentDir, record("evaluation-3"));
    truncateSync(logPath, limit);
    await writeAutoModeCalibrationRecord(agentDir, record("evaluation-4"));

    const backup = readFileSync(rotatedPath, "utf8");
    expect(backup).toContain("evaluation-2");
    expect(backup).toContain("evaluation-3");
    expect(backup).not.toContain("evaluation-1");
    expect(JSON.parse(readFileSync(logPath, "utf8"))).toEqual(record("evaluation-4"));
  });

  it("serializes concurrent writers without losing JSONL records", async () => {
    const agentDir = tempDir();
    await Promise.all(Array.from({ length: 4 }, (_, index) =>
      writeAutoModeCalibrationRecord(agentDir, record("evaluation-" + index)),
    ));

    const lines = readFileSync(join(agentDir, "logs", "auto-mode-calibration.jsonl"), "utf8")
      .trim().split("\n").map((line) => JSON.parse(line) as AutoModeCalibrationRecord);
    expect(lines.map(({ evaluationId }) => evaluationId).sort()).toEqual([
      "evaluation-0", "evaluation-1", "evaluation-2", "evaluation-3",
    ]);
  });
});
