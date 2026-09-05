import type {
  BashOperations,
  BashSpawnContext,
} from "@earendil-works/pi-coding-agent";

import { checkSandboxStatus, type SandboxStatus } from "../status.js";
import { extractAllNetworkTargets } from "../../network/domain-extractor.js";
import {
  buildBwrapCommand,
  resolveSandboxProfile,
  type UnmaskedPath,
} from "../bwrap-command.js";
import {
  normalizeSandboxConfig,
} from "../settings.js";
import type { SandboxBackend, SandboxOperationsInput, SandboxWrapInput, SandboxWrapResult } from "../backend.js";
import type { SandboxConfig, ResolvedSandboxProfile } from "../types.js";

export interface ResolvedBwrapProfileResult {
  profile: ResolvedSandboxProfile;
  needsNetwork: boolean;
  bwrapCommand: string[];
}

export interface BwrapBackendDeps {
  checkSandboxStatus: (runnerPath: string | null) => SandboxStatus;
  extractAllNetworkTargets: (command: string) => string[];
  resolveSandboxProfile: (config: SandboxConfig, profileName?: string) => ResolvedSandboxProfile;
  buildBwrapCommand: typeof buildBwrapCommand;
  normalizeSandboxConfig: (raw: unknown) => SandboxConfig;
  loadSpawn: () => Promise<{ spawn: typeof import("node:child_process").spawn }>;
}

export const DEFAULT_BWRAP_BACKEND_DEPS: BwrapBackendDeps = {
  checkSandboxStatus,
  extractAllNetworkTargets,
  resolveSandboxProfile,
  buildBwrapCommand,
  normalizeSandboxConfig,
  loadSpawn: async () => await import("node:child_process"),
};

function shellQuote(arg: string): string {
  if (arg.includes("\0")) {
    throw new Error(`Cannot shell-quote argument containing NUL byte`);
  }
  if (/^[a-zA-Z0-9_\/.\-+:]+$/.test(arg)) {
    return arg;
  }
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

function bwrapCommandToShellString(args: string[]): string {
  return args.map(shellQuote).join(" ");
}

export function resolveEffectiveBwrapProfile(
  deps: BwrapBackendDeps,
  command: string,
  sandboxConfig: SandboxConfig,
  cwd: string,
  unmaskedPaths?: UnmaskedPath[],
  preResolvedProfile?: ResolvedSandboxProfile,
  secretEnv?: Record<string, string>,
): ResolvedBwrapProfileResult | { error: string } | null {
  if (!sandboxConfig.enabled) return null;

  const status = deps.checkSandboxStatus(sandboxConfig.runnerPath ?? null);
  if (!status.available) {
    return { error: status.error ?? "Sandbox enabled but bwrap not available" };
  }

  const domains = deps.extractAllNetworkTargets(command);
  const needsNetwork = domains.length > 0;

  const profile = preResolvedProfile ?? (() => {
    const profileName = needsNetwork ? "online-dev" : sandboxConfig.defaultProfile;
    return deps.resolveSandboxProfile(sandboxConfig, profileName);
  })();

  const repoRoot = cwd;
  const { command: bwrapCommand } = deps.buildBwrapCommand(
    command.length > 0 ? ["bash", "-lc", command] : command.split(" "),
    { cwd, repoRoot, profile, config: sandboxConfig, unmaskedPaths, secretEnv },
  );

  return { profile, needsNetwork, bwrapCommand };
}

export function createBwrapBackend(
  deps: Partial<BwrapBackendDeps> = {},
): SandboxBackend {
  const resolvedDeps: BwrapBackendDeps = {
    ...DEFAULT_BWRAP_BACKEND_DEPS,
    ...deps,
  };

  return {
    kind: "bwrap",
    wrapCommand(input: SandboxWrapInput): SandboxWrapResult {
      const result = resolveEffectiveBwrapProfile(
        resolvedDeps,
        input.command,
        input.sandboxConfig,
        input.cwd,
        input.unmaskedPaths,
        input.preResolvedProfile,
        input.secretEnv,
      );
      if (result === null) return undefined;
      if ("error" in result) {
        return { block: true, reason: result.error };
      }
      return { command: bwrapCommandToShellString(result.bwrapCommand) };
    },
    createBashOperations(input: SandboxOperationsInput): BashOperations {
      return {
        exec: async (command, workDir, options) => {
          const normalizedConfig = resolvedDeps.normalizeSandboxConfig(
            input.sandboxConfig,
          );

          const domains = resolvedDeps.extractAllNetworkTargets(command);
          const needsNetwork = domains.length > 0;
          const profileName = needsNetwork
            ? "online-dev"
            : normalizedConfig.defaultProfile;
          const profile = input.preResolvedProfile ?? resolvedDeps.resolveSandboxProfile(normalizedConfig, profileName);

          const { command: bwrapArgs } = resolvedDeps.buildBwrapCommand(
            ["bash", "-lc", command],
            {
              cwd: workDir ?? input.cwd,
              repoRoot: workDir ?? input.cwd,
              profile,
              config: normalizedConfig,
              unmaskedPaths: input.unmaskedPaths,
              secretEnv: input.secretEnv,
            },
          );

          const { spawn } = await resolvedDeps.loadSpawn();
          const child = spawn(bwrapArgs[0]!, bwrapArgs.slice(1), {
            cwd: workDir ?? input.cwd,
            env: options.env,
            signal: options.signal,
          });

          child.stdout?.on("data", (data: Buffer) => {
            options.onData?.(data);
          });

          child.stderr?.on("data", (data: Buffer) => {
            options.onData?.(data);
          });

          return new Promise<{ exitCode: number | null }>((resolve) => {
            child.on("close", (code) => {
              resolve({ exitCode: code });
            });

            child.on("error", (err) => {
              options.onData?.(Buffer.from(`Sandbox error: ${err.message}\n`));
              resolve({ exitCode: 1 });
            });

            if (options.timeout) {
              setTimeout(() => {
                child.kill();
                resolve({ exitCode: null });
              }, options.timeout);
            }
          });
        },
      };
    },
  };
}
