import { existsSync } from "node:fs";
import { execSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

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

export function isCommandAvailable(command: string): boolean {
  try {
    execSync(`command -v ${command}`, { stdio: "ignore" });
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
  const requiredCommands = input.platform === "linux"
    ? ["rg", "bwrap", "socat"]
    : [];
  for (const name of requiredCommands) {
    dependencyChecks.push({
      name,
      available: input.commandAvailable(name),
    });
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
      error: `Missing SRT runtime dependencies: ${missing.join(", ")}.`,
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
