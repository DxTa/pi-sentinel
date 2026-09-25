import { existsSync, rmSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BashOperations } from "@earendil-works/pi-coding-agent";

import type { SandboxBackend, SandboxOperationsInput, SandboxWrapInput, SandboxWrapResult } from "../backend.js";
import { shouldBypassSandboxCommand } from "../bypass-command.js";
import type { SrtCommandSpec } from "../srt-command-spec.js";
import { buildSrtCommandSpec, buildSrtCommandSpecAsync } from "../srt-command-spec.js";
import { buildSrtRuntimeConfig } from "../srt-runtime-config.js";
import { summarizeEnvironmentSizes } from "../spawn-diagnostics.js";
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
  onE2Big?: (details: Record<string, unknown>) => void;
}

export const DEFAULT_SRT_HELPER_ENV = "PI_SRT_HELPER_INPUT_B64";
export const DEFAULT_SRT_HELPER_INPUT_FILE_ENV = "PI_SRT_HELPER_INPUT_FILE";
const MAX_INLINE_HELPER_INPUT_BYTES = 64 * 1024;

type HelperInputTransport = {
  environmentName: typeof DEFAULT_SRT_HELPER_ENV | typeof DEFAULT_SRT_HELPER_INPUT_FILE_ENV;
  value: string;
  helperPayloadBytes: number;
  cleanup?: () => void;
};

type SpawnInput = {
  route: string;
  command: string;
  env: NodeJS.ProcessEnv;
  helperPayloadBytes?: number;
};

type SrtHelperLaunch =
  | {
      child: ReturnType<typeof import("node:child_process").spawn>;
      transport: HelperInputTransport;
      spawnInput: SpawnInput;
    }
  | { errorMessage: string };

function shellQuote(arg: string): string {
  if (arg.includes("\0")) {
    throw new Error("Cannot shell-quote argument containing NUL byte");
  }
  if (/^[a-zA-Z0-9_\/.\-+:=]+$/.test(arg)) {
    return arg;
  }
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

async function createHelperInputTransport(input: SrtHelperInput): Promise<HelperInputTransport> {
  const serialized = JSON.stringify(input);
  const helperPayloadBytes = Buffer.byteLength(serialized, "utf8");
  if (helperPayloadBytes <= MAX_INLINE_HELPER_INPUT_BYTES) {
    const encoded = Buffer.from(serialized, "utf8").toString("base64");
    if (Buffer.byteLength(encoded, "utf8") <= MAX_INLINE_HELPER_INPUT_BYTES) {
      return { environmentName: DEFAULT_SRT_HELPER_ENV, value: encoded, helperPayloadBytes };
    }
  }

  const directory = await mkdtemp(join(tmpdir(), "pi-srt-helper-"));
  const file = join(directory, "input.json");
  try {
    await writeFile(file, serialized, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    await rm(directory, { recursive: true, force: true }).catch(() => {});
    throw error;
  }

  return {
    environmentName: DEFAULT_SRT_HELPER_INPUT_FILE_ENV,
    value: file,
    helperPayloadBytes,
    cleanup: () => {
      try {
        rmSync(directory, { recursive: true, force: true });
      } catch {
        // Cleanup must not change command results.
      }
    },
  };
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

function reportSpawnE2Big(
  deps: SrtBackendDeps,
  error: NodeJS.ErrnoException,
  input: SpawnInput,
): void {
  if (error.code !== "E2BIG" || !deps.onE2Big) return;

  deps.onE2Big({
    route: input.route,
    errorCode: "E2BIG",
    commandBytes: Buffer.byteLength(input.command, "utf8"),
    spawnEnvironment: summarizeEnvironmentSizes(input.env),
    ...(input.helperPayloadBytes === undefined ? {} : { helperPayloadBytes: input.helperPayloadBytes }),
  });
}

async function wrapSrtCommand(
  deps: SrtBackendDeps,
  input: SandboxWrapInput,
  helperPath: string,
): Promise<SandboxWrapResult> {
  let transport: HelperInputTransport | undefined;
  try {
    const helperInput = await buildHelperInputAsync(deps, input, input.command);
    transport = await createHelperInputTransport(helperInput);
    const b64Value = transport.environmentName === DEFAULT_SRT_HELPER_ENV
      ? shellQuote(transport.value)
      : "''";
    const fileValue = transport.environmentName === DEFAULT_SRT_HELPER_INPUT_FILE_ENV
      ? shellQuote(transport.value)
      : "''";
    const command = `${DEFAULT_SRT_HELPER_ENV}=${b64Value} ${DEFAULT_SRT_HELPER_INPUT_FILE_ENV}=${fileValue} ${shellQuote(deps.processExecPath())} ${shellQuote(helperPath)}`;
    return {
      command,
      helperPayloadBytes: transport.helperPayloadBytes,
      rawCommandBytes: Buffer.byteLength(helperInput.command, "utf8"),
      ...(transport.cleanup ? { cleanup: transport.cleanup } : {}),
    };
  } catch (error) {
    transport?.cleanup?.();
    const message = error instanceof Error ? error.message : String(error);
    return { block: true, reason: message };
  }
}

async function launchSrtHelper(input: {
  deps: SrtBackendDeps;
  backendInput: SandboxOperationsInput;
  command: string;
  workDir: string;
  helperPath: string;
  env: NodeJS.ProcessEnv | undefined;
  signal: AbortSignal | undefined;
}): Promise<SrtHelperLaunch> {
  let helperInput: SrtHelperInput;
  let transport: HelperInputTransport;
  try {
    helperInput = await buildHelperInputAsync(
      input.deps,
      { ...input.backendInput, cwd: input.workDir },
      input.command,
    );
    transport = await createHelperInputTransport(helperInput);
  } catch (error) {
    return { errorMessage: error instanceof Error ? error.message : String(error) };
  }

  let spawn: typeof import("node:child_process").spawn;
  try {
    ({ spawn } = await input.deps.loadSpawn());
  } catch (error) {
    transport.cleanup?.();
    throw error;
  }
  const spawnEnv = { ...(input.env ?? process.env) };
  delete spawnEnv[DEFAULT_SRT_HELPER_ENV];
  delete spawnEnv[DEFAULT_SRT_HELPER_INPUT_FILE_ENV];
  spawnEnv[transport.environmentName] = transport.value;
  const spawnInput: SpawnInput = {
    route: "srt-helper",
    command: input.command,
    env: spawnEnv,
    helperPayloadBytes: transport.helperPayloadBytes,
  };

  try {
    const child = spawn(input.deps.processExecPath(), [input.helperPath], {
      cwd: input.workDir,
      env: spawnEnv,
      signal: input.signal,
      detached: input.deps.platform() !== "win32",
    });
    return { child, transport, spawnInput };
  } catch (error) {
    reportSpawnE2Big(input.deps, error as NodeJS.ErrnoException, spawnInput);
    transport.cleanup?.();
    throw error;
  }
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
      if (shouldBypassSandboxCommand(input.command, input.sandboxConfig.bypassCommands)) {
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

      return wrapSrtCommand(resolvedDeps, input, helperPath);
    },
    createBashOperations(input: SandboxOperationsInput): BashOperations {
      return {
        exec: async (command, workDir, options) => {
          if (shouldBypassSandboxCommand(command, input.sandboxConfig.bypassCommands)) {
            const { spawn } = await resolvedDeps.loadSpawn();
            const spawnEnv = { ...(options.env ?? process.env) };
            const spawnInput = { route: "srt-bypass", command, env: spawnEnv };
            let child: ReturnType<typeof spawn>;
            try {
              child = spawn("bash", ["-lc", command], {
                cwd: workDir ?? input.cwd,
                env: spawnEnv,
                signal: options.signal,
                detached: resolvedDeps.platform() !== "win32",
              });
            } catch (error) {
              reportSpawnE2Big(resolvedDeps, error as NodeJS.ErrnoException, spawnInput);
              throw error;
            }

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
                reportSpawnE2Big(resolvedDeps, err as NodeJS.ErrnoException, spawnInput);
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

          const launch = await launchSrtHelper({
            deps: resolvedDeps,
            backendInput: input,
            command,
            workDir: workDir ?? input.cwd,
            helperPath,
            env: options.env,
            signal: options.signal,
          });
          if ("errorMessage" in launch) {
            options.onData?.(Buffer.from(`${launch.errorMessage}\n`));
            return { exitCode: 1 };
          }
          const { child, transport, spawnInput } = launch;

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
              transport.cleanup?.();
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
              reportSpawnE2Big(resolvedDeps, err as NodeJS.ErrnoException, spawnInput);
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
