/** Outcome of a single permission gate evaluation. */
export type GateOutcome =
  | { action: "allow" }
  | { action: "block"; reason: string };

/** Pre-validated context shared across all gates. */
export interface ToolCallContext {
  toolName: string;
  agentName: string | null;
  input: unknown;
  toolCallId: string;
  cwd: string | undefined;
  sandboxed?: boolean;
  /** Active permission mode; classic `yolo` skips forced prompts and legacy external-write blocks. */
  mode?: string;
  autoModeHardRuleHit?: boolean;
  autoModeWorkspaceLocal?: boolean;
  autoModeTargetsWorkspace?: boolean;
  autoModeCommand?: string;
  /** Redacted inner Bash commands, classified one by one. */
  autoModeUnits?: readonly string[];
  /** Inner Bash commands cannot all be read statically. */
  autoModeOpaque?: boolean;
  /** Server-declared MCP hint; untrusted, so it can only make auto mode stricter. */
  mcpDestructiveHint?: boolean;
}
