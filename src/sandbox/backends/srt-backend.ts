import { existsSync } from "node:fs";
import type { BashOperations } from "@earendil-works/pi-coding-agent";

import type { SandboxBackend, SandboxOperationsInput, SandboxWrapInput, SandboxWrapResult } from "../backend.js";
import { wildcardMatch } from "../../wildcard-matcher.js";
import type { SrtCommandSpec } from "../srt-command-spec.js";
import { buildSrtCommandSpec, buildSrtCommandSpecAsync } from "../srt-command-spec.js";
import { buildSrtRuntimeConfig } from "../srt-runtime-config.js";
import {
  checkSrtStatus,
  defaultSrtHelperPath,
  isCommandAvailable,
  isSrtPackageAvailable,
  type SrtStatus,
} from "../srt-status.js";

export interface SrtHelperInput {
  command: string;
  cwd: string;
  runtimeConfig: ReturnType<typeof buildSrtRuntimeConfig>;
  unmatchedHostAction: SrtCommandSpec["networkPlan"]["unmatchedHostAction"];
  maskedShimPlan: SrtCommandSpec["maskedShimPlan"];
  unmaskedPaths: SrtCommandSpec["unmaskedPaths"];
  envAllowPatterns?: SrtCommandSpec["envAllowPatterns"];
  envDenyPatterns: SrtCommandSpec["envDenyPatterns"];
  execShimPlan: SrtCommandSpec["execShimPlan"];
}

export interface SrtBackendDeps {
  helperPath: () => string;
  processExecPath: () => string;
  platform: () => string;
  packageAvailable: () => boolean;
  commandAvailable: (command: string) => boolean;
  checkSrtStatus: (input: {
    platform: string;
    entrypointPath: string | null;
    hasEntrypoint: boolean;
    packageAvailable: boolean;
    commandAvailable: (command: string) => boolean;
  }) => SrtStatus;
  buildSrtCommandSpec: typeof buildSrtCommandSpec;
  buildSrtCommandSpecAsync?: typeof buildSrtCommandSpecAsync;
  buildSrtRuntimeConfig: typeof buildSrtRuntimeConfig;
  loadSpawn: () => Promise<{ spawn: typeof import("node:child_process").spawn }>;
}

export const DEFAULT_SRT_HELPER_ENV = "PI_SRT_HELPER_INPUT_B64";

function shellQuote(arg: string): string {
  if (arg.includes("\0")) {
    throw new Error("Cannot shell-quote argument containing NUL byte");
  }
  if (/^[a-zA-Z0-9_\/.\-+:=]+$/.test(arg)) {
    return arg;
  }
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

function encodeHelperInput(input: SrtHelperInput): string {
  return Buffer.from(JSON.stringify(input), "utf8").toString("base64");
}

const DEFAULT_DEPS: SrtBackendDeps = {
  helperPath: () => defaultSrtHelperPath(null),
  processExecPath: () => process.execPath,
  platform: () => process.platform,
  packageAvailable: isSrtPackageAvailable,
  commandAvailable: isCommandAvailable,
  checkSrtStatus,
  buildSrtCommandSpec,
  buildSrtCommandSpecAsync,
  buildSrtRuntimeConfig,
  loadSpawn: async () => await import("node:child_process"),
};

function matchesBypassCommand(command: string, patterns?: string[]): boolean {
  if (!patterns || patterns.length === 0) return false;
  const cmd = command.trim();
  if (cmd.length === 0) return false;
  return patterns.some((p) => wildcardMatch(p, cmd));
}

function killProcessGroup(pid: number | undefined, signal: NodeJS.Signals): void {
  if (!pid || process.platform === "win32") return;
  try {
    process.kill(-pid, signal);
  } catch {
    // The helper or its process group may already be gone.
  }
}

function buildSpecInput(
  input: SandboxWrapInput | SandboxOperationsInput,
  command: string,
): Parameters<typeof buildSrtCommandSpec>[0] {
  return {
    command,
    cwd: input.cwd,
    repoRoot: input.repoRoot ?? input.cwd,
    sandboxConfig: input.sandboxConfig,
    profile: input.preResolvedProfile!,
    unifiedConfig: input.unifiedConfig,
    approvedDomains: input.approvedDomains,
    unmaskedPaths: input.unmaskedPaths,
    secretEnv: input.secretEnv,
  };
}

function helperInputFromSpec(
  deps: SrtBackendDeps,
  spec: SrtCommandSpec,
): SrtHelperInput {
  return {
    command: spec.command,
    cwd: spec.cwd,
    runtimeConfig: deps.buildSrtRuntimeConfig(spec),
    unmatchedHostAction: spec.networkPlan.unmatchedHostAction,
    maskedShimPlan: spec.maskedShimPlan,
    unmaskedPaths: spec.unmaskedPaths,
    envAllowPatterns: spec.envAllowPatterns,
    envDenyPatterns: spec.envDenyPatterns,
    execShimPlan: spec.execShimPlan,
  };
}

async function buildHelperInputAsync(
  deps: SrtBackendDeps,
  input: SandboxWrapInput | SandboxOperationsInput,
  command: string,
): Promise<SrtHelperInput> {
  const buildSpec = deps.buildSrtCommandSpecAsync ?? deps.buildSrtCommandSpec;
  return helperInputFromSpec(deps, await buildSpec(buildSpecInput(input, command)));
}

export function createSrtBackend(
  deps: Partial<SrtBackendDeps> = {},
): SandboxBackend {
  const resolvedDeps: SrtBackendDeps = { ...DEFAULT_DEPS, ...deps };
  if (deps.buildSrtCommandSpec && !deps.buildSrtCommandSpecAsync) {
    resolvedDeps.buildSrtCommandSpecAsync = undefined;
  }

  return {
    kind: "srt",
    wrapCommand: async (input: SandboxWrapInput): Promise<SandboxWrapResult> => {
      if (matchesBypassCommand(input.command, input.sandboxConfig.bypassCommands)) {
        return { command: input.command };
      }

      const helperPath = resolvedDeps.helperPath();
      const status = resolvedDeps.checkSrtStatus({
        platform: resolvedDeps.platform(),
        entrypointPath: helperPath,
        hasEntrypoint: existsSync(helperPath),
        packageAvailable: resolvedDeps.packageAvailable(),
        commandAvailable: resolvedDeps.commandAvailable,
      });
      if (!status.available) {
        return { block: true, reason: status.error ?? "SRT backend unavailable." };
      }
      if (!input.preResolvedProfile) {
        return { block: true, reason: "SRT backend requires pre-resolved sandbox profile." };
      }

      try {
        const helperInput = await buildHelperInputAsync(resolvedDeps, input, input.command);
        const encoded = encodeHelperInput(helperInput);
        const command = `${DEFAULT_SRT_HELPER_ENV}=${shellQuote(encoded)} ${shellQuote(resolvedDeps.processExecPath())} ${shellQuote(helperPath)}`;
        return { command };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { block: true, reason: message };
      }
    },
    createBashOperations(input: SandboxOperationsInput): BashOperations {
      return {
        exec: async (command, workDir, options) => {
          if (matchesBypassCommand(command, input.sandboxConfig.bypassCommands)) {
            const { spawn } = await resolvedDeps.loadSpawn();
            const child = spawn("bash", ["-lc", command], {
              cwd: workDir ?? input.cwd,
              env: options.env ?? process.env,
              signal: options.signal,
              detached: resolvedDeps.platform() !== "win32",
            });

            child.stdout?.on("data", (data: Buffer) => options.onData?.(data));
            child.stderr?.on("data", (data: Buffer) => options.onData?.(data));

            return new Promise<{ exitCode: number | null }>((resolve) => {
              let settled = false;
              let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
              let forceKillHandle: ReturnType<typeof setTimeout> | undefined;
              const finish = (exitCode: number | null) => {
                if (settled) return;
                settled = true;
                if (timeoutHandle) clearTimeout(timeoutHandle);
                if (forceKillHandle) clearTimeout(forceKillHandle);
                options.signal?.removeEventListener("abort", terminate);
                resolve({ exitCode });
              };
              const terminate = () => {
                if (settled) return;
                killProcessGroup(child.pid, "SIGTERM");
                child.kill();
                forceKillHandle = setTimeout(() => {
                  killProcessGroup(child.pid, "SIGKILL");
                  child.kill();
                }, 250);
              };
              child.on("close", (code) => finish(code));
              child.on("error", (err) => {
                options.onData?.(Buffer.from(`Bypass shell error: ${err.message}\n`));
                finish(1);
              });
              options.signal?.addEventListener("abort", terminate, { once: true });
              if (options.timeout) timeoutHandle = setTimeout(terminate, options.timeout);
            });
          }

          const helperPath = resolvedDeps.helperPath();
          const status = resolvedDeps.checkSrtStatus({
            platform: resolvedDeps.platform(),
            entrypointPath: helperPath,
            hasEntrypoint: existsSync(helperPath),
            packageAvailable: resolvedDeps.packageAvailable(),
            commandAvailable: resolvedDeps.commandAvailable,
          });
          if (!status.available) {
            options.onData?.(Buffer.from(`SRT backend unavailable: ${status.error}\n`));
            return { exitCode: 1 };
          }
          if (!input.preResolvedProfile) {
            options.onData?.(Buffer.from("SRT backend requires pre-resolved sandbox profile.\n"));
            return { exitCode: 1 };
          }

          let encoded: string;
          try {
            const helperInput = await buildHelperInputAsync(
              resolvedDeps,
              { ...input, cwd: workDir ?? input.cwd },
              command,
            );
            encoded = encodeHelperInput(helperInput);
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            options.onData?.(Buffer.from(`${message}\n`));
            return { exitCode: 1 };
          }
          const { spawn } = await resolvedDeps.loadSpawn();
          const child = spawn(resolvedDeps.processExecPath(), [helperPath], {
            cwd: workDir ?? input.cwd,
            env: {
              ...(options.env ?? process.env),
              [DEFAULT_SRT_HELPER_ENV]: encoded,
            },
            signal: options.signal,
            detached: resolvedDeps.platform() !== "win32",
          });

          child.stdout?.on("data", (data: Buffer) => options.onData?.(data));
          child.stderr?.on("data", (data: Buffer) => options.onData?.(data));

          return new Promise<{ exitCode: number | null }>((resolve) => {
            let settled = false;
            let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
            let forceKillHandle: ReturnType<typeof setTimeout> | undefined;
            const finish = (exitCode: number | null) => {
              if (settled) return;
              settled = true;
              if (timeoutHandle) clearTimeout(timeoutHandle);
              if (forceKillHandle) clearTimeout(forceKillHandle);
              options.signal?.removeEventListener("abort", terminate);
              resolve({ exitCode });
            };
            const terminate = () => {
              if (settled) return;
              killProcessGroup(child.pid, "SIGTERM");
              child.kill();
              forceKillHandle = setTimeout(() => {
                killProcessGroup(child.pid, "SIGKILL");
                child.kill();
              }, 250);
            };
            child.on("close", (code) => finish(code));
            child.on("error", (err) => {
              options.onData?.(Buffer.from(`SRT helper error: ${err.message}\n`));
              finish(1);
            });
            options.signal?.addEventListener("abort", terminate, { once: true });
            if (options.timeout) timeoutHandle = setTimeout(terminate, options.timeout);
          });
        },
      };
    },
  };
}
