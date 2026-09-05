/**
 * Sandbox gate handler compatibility wrappers.
 *
 * Current behavior still uses bwrap backend, but exported functions now route
 * through an explicit sandbox backend implementation so future SRT integration
 * has a real seam.
 */

import type { BashOperations } from "@earendil-works/pi-coding-agent";

import {
  createBwrapBackend,
  DEFAULT_BWRAP_BACKEND_DEPS,
  resolveEffectiveBwrapProfile,
} from "./backends/bwrap-backend.js";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";
import type { UnmaskedPath } from "./bwrap-command.js";

const defaultBwrapBackend = createBwrapBackend();

export function resolveEffectiveProfile(
  command: string,
  sandboxConfig: SandboxConfig,
  cwd: string,
  unmaskedPaths?: UnmaskedPath[],
  preResolvedProfile?: ResolvedSandboxProfile,
  secretEnv?: Record<string, string>,
) {
  return resolveEffectiveBwrapProfile(
    DEFAULT_BWRAP_BACKEND_DEPS,
    command,
    sandboxConfig,
    cwd,
    unmaskedPaths,
    preResolvedProfile,
    secretEnv,
  );
}

export function wrapCommandInSandbox(
  command: string,
  sandboxConfig: SandboxConfig,
  cwd: string,
  unmaskedPaths?: UnmaskedPath[],
  preResolvedProfile?: ResolvedSandboxProfile,
  secretEnv?: Record<string, string>,
): { command: string } | { block: true; reason: string } | undefined {
  const result = defaultBwrapBackend.wrapCommand({
    command,
    sandboxConfig,
    cwd,
    unmaskedPaths,
    preResolvedProfile,
    secretEnv,
  });
  if (result instanceof Promise) {
    throw new Error("Synchronous bubblewrap wrapper returned a promise.");
  }
  return result;
}

export function createSandboxedBashOperations(
  sandboxConfig: SandboxConfig,
  cwd: string,
  unmaskedPaths?: UnmaskedPath[],
  preResolvedProfile?: ResolvedSandboxProfile,
  secretEnv?: Record<string, string>,
): BashOperations {
  return defaultBwrapBackend.createBashOperations({
    sandboxConfig,
    cwd,
    unmaskedPaths,
    preResolvedProfile,
    secretEnv,
  });
}
