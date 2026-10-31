import {
  chmodSync,
  closeSync,
  existsSync,
  fchmodSync,
  mkdirSync,
  openSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import { withFileLock } from "./auto-mode-file-lock.ts";
import type { AutoModeCalibrationRecord } from "./auto-mode-evaluator";

const MAX_LOG_BYTES = 50 * 1024 * 1024;
const LOG_FILE_NAME = "auto-mode-calibration.jsonl";
const LOCK_FILE_NAME = ".auto-mode-calibration.lock";

export async function writeAutoModeCalibrationRecord(
  agentDir: string,
  record: AutoModeCalibrationRecord,
): Promise<void> {
  const logDir = join(agentDir, "logs");
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  chmodSync(logDir, 0o700);

  const logPath = join(logDir, LOG_FILE_NAME);
  const line = JSON.stringify(record) + "\n";
  await withFileLock(join(logDir, LOCK_FILE_NAME), async () => {
    if (
      existsSync(logPath) &&
      statSync(logPath).size + Buffer.byteLength(line) > MAX_LOG_BYTES
    ) {
      const rotatedPath = logPath + ".1";
      chmodSync(logPath, 0o600);
      rmSync(rotatedPath, { force: true });
      renameSync(logPath, rotatedPath);
    }

    const fd = openSync(logPath, "a", 0o600);
    try {
      fchmodSync(fd, 0o600);
      writeFileSync(fd, line, { encoding: "utf8" });
    } finally {
      closeSync(fd);
    }
  });
}
