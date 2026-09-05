/**
 * Sandbox status checking — bwrap availability, runner integrity.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { execSync } from "node:child_process";
import { resolveBwrapRunnerPath } from "./settings.js";

export interface SandboxStatus {
  available: boolean;
  bwrapBinary: boolean;
  bwrapVersion: string | null;
  runnerPath: string | null;
  runnerExists: boolean;
  error?: string;
}

/**
 * Check sandbox availability and integrity.
 */
export function checkSandboxStatus(runnerPath: string | null): SandboxStatus {
  // Check bwrap binary
  let bwrapBinary = false;
  let bwrapVersion: string | null = null;
  try {
    bwrapVersion = execSync("bwrap --version", { encoding: "utf-8" }).trim();
    bwrapBinary = true;
  } catch {
    bwrapBinary = false;
  }

  // Check runner script
  const resolvedRunner = resolveBwrapRunnerPath(runnerPath);
  const runnerExists = existsSync(resolvedRunner);

  if (!bwrapBinary) {
    return {
      available: false,
      bwrapBinary: false,
      bwrapVersion: null,
      runnerPath: resolvedRunner,
      runnerExists,
      error: "bwrap binary not found on PATH. Install bubblewrap package.",
    };
  }

  if (!runnerExists) {
    return {
      available: false,
      bwrapBinary: true,
      bwrapVersion,
      runnerPath: resolvedRunner,
      runnerExists: false,
      error: `bwrap runner script not found at ${resolvedRunner}. Set PI_BWRAP_RUNNER or install the runner.`,
    };
  }

  return {
    available: true,
    bwrapBinary: true,
    bwrapVersion,
    runnerPath: resolvedRunner,
    runnerExists: true,
  };
}