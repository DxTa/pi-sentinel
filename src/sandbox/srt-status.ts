import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { ripgrepCommand } from "./ripgrep.js";

const require = createRequire(import.meta.url);

export interface SrtDependencyCheck {
  name: string;
  available: boolean;
}

export interface SrtStatusInput {
  platform: string;
  entrypointPath: string | null;
  hasEntrypoint: boolean;
  packageAvailable: boolean;
  commandAvailable: (command: string) => boolean;
  /** Ripgrep command SRT will run on Linux; defaults to `rg` on PATH. */
  ripgrepCommand?: string;
}

export interface SrtStatus {
  available: boolean;
  platform: string;
  packageAvailable: boolean;
  entrypointPath: string | null;
  entrypointExists: boolean;
  dependencyChecks: SrtDependencyCheck[];
  error?: string;
}

export function defaultSrtHelperPath(configRunnerPath: string | null): string {
  if (configRunnerPath) return resolve(configRunnerPath);
  return resolve(fileURLToPath(new URL("../../bin/sandbox-run.mjs", import.meta.url)));
}

export function isSrtPackageAvailable(): boolean {
  try {
    require.resolve("@anthropic-ai/sandbox-runtime");
    return true;
  } catch {
    return false;
  }
}

export { helperRuntimePath } from "../host-runtime.js";

export function isCommandAvailable(command: string): boolean {
  try {
    execFileSync("/bin/sh", ["-c", 'command -v "$1"', "sh", command], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export function defaultSrtStatus(configRunnerPath: string | null): SrtStatus {
  const entrypointPath = defaultSrtHelperPath(configRunnerPath);
  return checkSrtStatus({
    platform: process.platform,
    entrypointPath,
    hasEntrypoint: existsSync(entrypointPath),
    packageAvailable: isSrtPackageAvailable(),
    commandAvailable: isCommandAvailable,
    ripgrepCommand: ripgrepCommand(),
  });
}

export function checkSrtStatus(input: SrtStatusInput): SrtStatus {
  if (!input.packageAvailable) {
    return {
      available: false,
      platform: input.platform,
      packageAvailable: false,
      entrypointPath: input.entrypointPath,
      entrypointExists: input.hasEntrypoint,
      dependencyChecks: [],
      error: "@anthropic-ai/sandbox-runtime package not available to runner.",
    };
  }

  if (input.entrypointPath && !input.hasEntrypoint) {
    return {
      available: false,
      platform: input.platform,
      packageAvailable: true,
      entrypointPath: input.entrypointPath,
      entrypointExists: false,
      dependencyChecks: [],
      error: `SRT entrypoint not found at ${input.entrypointPath}.`,
    };
  }

  if (input.platform !== "darwin" && input.platform !== "linux") {
    return {
      available: false,
      platform: input.platform,
      packageAvailable: true,
      entrypointPath: input.entrypointPath,
      entrypointExists: input.hasEntrypoint,
      dependencyChecks: [],
      error: `SRT sandbox not supported on ${input.platform}.`,
    };
  }

  const dependencyChecks: SrtDependencyCheck[] = [];
  if (input.platform === "linux") {
    dependencyChecks.push({ name: "rg", available: input.commandAvailable(input.ripgrepCommand ?? "rg") });
    for (const name of ["bwrap", "socat"]) {
      dependencyChecks.push({ name, available: input.commandAvailable(name) });
    }
  }

  const missing = dependencyChecks.filter((dep) => !dep.available).map((dep) => dep.name);
  if (missing.length > 0) {
    return {
      available: false,
      platform: input.platform,
      packageAvailable: true,
      entrypointPath: input.entrypointPath,
      entrypointExists: input.hasEntrypoint,
      dependencyChecks,
      error: `Missing SRT runtime dependencies: ${missing.join(", ")}. Run /sandbox-status for setup steps.`,
    };
  }

  return {
    available: true,
    platform: input.platform,
    packageAvailable: true,
    entrypointPath: input.entrypointPath,
    entrypointExists: input.hasEntrypoint,
    dependencyChecks,
  };
}
