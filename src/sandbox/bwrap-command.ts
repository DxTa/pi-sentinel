/**
 * Bubblewrap command builder for Pi sandboxing.
 * Hardened from ape-dev src/lib/sandbox.ts.
 *
 * Masked files are replaced with a "(masked)" content placeholder so that
 * `cat` shows "(masked)" instead of secrets, while `ls`/`find` still list
 * the filenames. Sockets (Docker, SSH, GPG) use /dev/null since you cannot
 * meaningfully cat() a Unix socket.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";
import {
  resolveBwrapRunnerPath,
  resolveSandboxBindPaths,
  validateSandboxBindPath,
  validateSandboxUnmaskPath,
} from "./settings.js";

export interface UnmaskedPath {
  /** Absolute path to the file. */
  path: string;
  /** Whether the file should be writable inside the sandbox. Default: false (read-only). */
  writable: boolean;
}

export interface BwrapCommandResult {
  command: string[];
  effectiveCwd: string | null;
  /**
   * Paths that were masked by default but should be unmasked (visible inside sandbox).
   * These are overriden via explicit bind mounts (last-entry-wins in bwrap).
   */
  unmaskedPaths?: UnmaskedPath[];
}

/**
 * Build the bwrap command array for a given profile and base command.
 *
 * @param opts.unmaskedPaths - Specific file paths that should NOT be masked,
 *   even if they match a masked glob pattern. When a user grants access
 *   to a previously-masked file, those paths are passed here to ensure
 *   they remain visible inside the sandbox via an explicit bind mount
 *   that overrides the "(masked)" content placeholder (bwrap uses last-entry-wins semantics).
 *   IMPORTANT: Unmasked paths default to read-only (--ro-bind) to prevent
 *   write escalation after a read-only approval. Use writable: true only
 *   when the user explicitly grants write access.
 *
 *   Unmasked paths override the "(masked)" content placeholder via bwrap's
 *   last-entry-wins semantics — they mount the real file over the placeholder.
 */
export function buildBwrapCommand(
  baseCommand: string[],
  opts: {
    cwd: string;
    repoRoot: string;
    profile: ResolvedSandboxProfile;
    config: SandboxConfig;
    /** Paths to exclude from masking (user-granted access). */
    unmaskedPaths?: UnmaskedPath[];
    /** Secret env names approved for this invocation only. Values stay in host env. */
    secretEnv?: Record<string, string>;
  },
): BwrapCommandResult {
  const bwrapRunner = resolveBwrapRunnerPath(opts.config.runnerPath ?? null);
  if (!existsSync(bwrapRunner)) {
    throw new Error(
      `Sandbox mode 'bwrap' requested but bwrap runner not found at ${bwrapRunner}. ` +
        "Set PI_BWRAP_RUNNER env var or install the runner.",
    );
  }

  const command: string[] = [
    bwrapRunner,
    "--cwd", opts.cwd,
    "--repo-root", opts.repoRoot,
    "--network", opts.profile.network ? "on" : "off",
  ];

  if (opts.profile.allowDocker) {
    command.push("--allow-docker");
  }

  // Global binds from config
  if (opts.config.roBinds?.length) {
    const resolved = resolveSandboxBindPaths(opts.config.roBinds, opts.repoRoot);
    for (const p of resolved) command.push("--ro-bind", p);
  }
  if (opts.config.rwBinds?.length) {
    const resolved = resolveSandboxBindPaths(opts.config.rwBinds, opts.repoRoot);
    for (const p of resolved) command.push("--rw-bind", p);
  }

  // Profile-specific binds
  if (opts.profile.roBinds?.length) {
    const resolved = resolveSandboxBindPaths(opts.profile.roBinds, opts.repoRoot);
    for (const p of resolved) command.push("--ro-bind", p);
  }
  if (opts.profile.rwBinds?.length) {
    const resolved = resolveSandboxBindPaths(opts.profile.rwBinds, opts.repoRoot);
    for (const p of resolved) command.push("--rw-bind", p);
  }

  // Masked paths (glob patterns) — applied by bwrap-run.sh via find + --ro-bind of
  // a "(masked)" placeholder file. Directories are still listable; only content is replaced.
  if (opts.profile.maskedPaths?.length) {
    command.push("--masked-paths", opts.profile.maskedPaths.join(","));
  }

  // Unmasked paths: explicit bind mounts for paths the user granted access to.
  // bwrap uses last-entry-wins semantics, so these overrides take precedence
  // over the "(masked)" placeholder applied by the masked-paths globs in bwrap-run.sh.
  // CRITICAL: Default to --ro-bind (read-only) to prevent write escalation.
  // A user who approves "read access" should not get write access.
  const unmaskedPaths = opts.unmaskedPaths ?? [];
  for (const entry of unmaskedPaths) {
    if (existsSync(entry.path)) {
      if (entry.writable) validateSandboxBindPath(entry.path);
      else validateSandboxUnmaskPath(entry.path);
      // Register the path as user-approved so bwrap-run.sh bypasses
      // sensitive-path validation for it
      command.push("--approved-unmask-path", entry.path);
      if (entry.writable) {
        command.push("--rw-bind", entry.path);
      } else {
        command.push("--ro-bind", entry.path);
      }
    }
  }

  // Invocation-scoped secret env approvals. Pass names only to this wrapper;
  // bwrap-run.sh reads values from its host environment for this run only.
  for (const name of Object.keys(opts.secretEnv ?? {})) {
    command.push("--secret-env", name);
  }

  // Env policy: only pass deny list. By default, bwrap-run.sh inherits the full
  // parent environment (no --clearenv). --env-deny can still block specific patterns.
  if (opts.profile.env?.deny?.length) {
    command.push("--env-deny", opts.profile.env.deny.join(","));
  }

  // Resource limits
  const limits = opts.profile.resourceLimits;
  if (limits?.pids) {
    command.push("--pids", String(limits.pids));
  }
  if (limits?.tmpfsSize) {
    command.push("--tmpfs-size", limits.tmpfsSize);
  }

  command.push("--", ...baseCommand);
  return { command, effectiveCwd: null, unmaskedPaths };
}

/**
 * Resolve the active sandbox profile from config.
 */
export function resolveSandboxProfile(
  config: SandboxConfig,
  profileName?: string,
): ResolvedSandboxProfile {
  const name = profileName ?? config.defaultProfile;
  const profile = Object.hasOwn(config.profiles, name)
    ? config.profiles[name]
    : undefined;
  if (!profile) {
    throw new Error(
      `Unknown sandbox profile '${name}'. Available: ${Object.keys(config.profiles).join(", ")}`,
    );
  }
  return { ...profile, name };
}