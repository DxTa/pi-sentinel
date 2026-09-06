/**
 * Sandbox types for bubblewrap integration.
 * Hardened from ape-dev src/lib/sandbox.ts.
 */

export type SandboxMode = "bwrap" | "none";

export interface SandboxEnvPolicy {
  /** Environment variables to pass through (exact names or patterns). */
  allow: string[];
  /** Environment variable patterns to deny (e.g., "*_API_KEY", "*_TOKEN"). */
  deny: string[];
}

export interface SandboxResourceLimits {
  /** Maximum number of PIDs in the sandbox. Default: 512 */
  pids?: number;
  /** Maximum tmpfs size in bytes for /tmp. Default: 1073741824 (1GB) */
  tmpfsSize?: string;
}

export interface SandboxProfile {
  /** Whether this profile allows network access. */
  network: boolean;
  /** Whether Docker socket is accessible. Default: false. */
  allowDocker?: boolean;
  /** Additional read-only bind mounts. */
  roBinds?: string[];
  /** Additional read-write bind mounts. */
  rwBinds?: string[];
  /** Environment variable policy. */
  env: SandboxEnvPolicy;
  /** Glob patterns for files to mask inside the sandbox.
   * Matched files are replaced with a "(masked)" content placeholder so that
   * `cat` shows "(masked)" instead of secrets, while `ls`/`find` still list
   * the filenames. These override any rw/ro mounts — secrets are always hidden. */
  maskedPaths: string[];
  /** Resource limits for the sandbox. */
  resourceLimits?: SandboxResourceLimits;
}

export type SandboxAuthExceptionStrategy = "ask-unmask" | "ask-bypass" | "deny";

export interface SandboxAuthExceptionRule {
  /** Raw shell command glob matched with wildcardMatch. */
  match: string;
  /** Optional auth kind selector (`ssh-auth`, `aws-auth`, or `*`). */
  kind?: string;
  /** Strategy to apply when the rule matches. */
  strategy: SandboxAuthExceptionStrategy;
}

export interface SandboxConfig {
  /** Whether sandboxing is enabled. Default: true. */
  enabled: boolean;
  /** Persisted coarse network capability granted to sandbox. */
  network?: boolean;
  /** Transitional backend selector. Default: srt. */
  backend?: "bwrap" | "srt";
  /** Predefined profiles. */
  profiles: Record<string, SandboxProfile>;
  /** Default profile name. */
  defaultProfile: string;
  /** Additional read-only bind mounts (added to all profiles). */
  roBinds?: string[];
  /** Additional read-write bind mounts (added to all profiles). */
  rwBinds?: string[];
  /** Path to bwrap-run.sh runner. Default: auto-detect. */
  runnerPath?: string | null;

  /** Command glob patterns (wildcardMatch) that skip the sandbox entirely.
   * Matched against the raw command string. Use for commands that require
   * capabilities the SRT sandbox cannot provide (e.g. AF_UNIX sockets for herdr). */
  bypassCommands?: string[];
  /** Optional command-specific auth exception policy. */
  authExceptions?: SandboxAuthExceptionRule[];
}

export interface ResolvedSandboxProfile extends SandboxProfile {
  /** The resolved profile name. */
  name: string;
}

export interface SandboxCheckResult {
  /** Whether sandbox should be applied. */
  sandbox: boolean;
  /** The resolved profile (null if sandbox is disabled). */
  profile: ResolvedSandboxProfile | null;
  /** The bwrap command (null if sandbox is disabled). */
  bwrapCommand: string[] | null;
  /** Error message if sandbox can't be applied. */
  error?: string;
}

const SANDBOX_MODES: Set<string> = new Set(["bwrap", "none"]);

/**
 * Sensitive paths that must NEVER be bind-mounted into a sandbox,
 * even when listed in roBinds/rwBinds.
 */
const SENSITIVE_BIND_SUFFIXES = [
  ".ssh",
  ".gnupg",
  ".aws",
  ".config/gcloud",
  ".kube",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".docker",
];

const SENSITIVE_BIND_PATHS = ["/etc/shadow", "/etc/sudoers"];

export {
  SANDBOX_MODES,
  SENSITIVE_BIND_SUFFIXES,
  SENSITIVE_BIND_PATHS,
};