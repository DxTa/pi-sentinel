/**
 * sentinel-creds — Credential leak guard for pi coding agents.
 *
 * Guards:
 *   1. output-scanner — pre-reads files before `read` tool calls and scans
 *      for secret patterns. Also intercepts `bash` commands that read file content.
 *   2. env-shield — blocks/restricts `bash` commands that dump environment variables.
 *   3. input-scanner — scans user messages and asks for confirmation when
 *      pasted credentials are detected.
 *   4. result-scanner — scans tool results for secret patterns and redacts them.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { mkdirSync, appendFileSync } from "node:fs";

import type { PromptWaitTracker } from "../prompt-state";
import {
  getScopedConfigPath,
  persistSentinelReadAllowedPathToConfig,
  type PersistentApprovalScope,
} from "../scoped-config";
import type { SentinelCredsConfig } from "./config";
import { loadSentinelCredsConfig } from "./config";
import {
  scanContentForSecrets,
  scanPathForSecrets,
  isBinaryContent,
  redactSecrets,
  MAX_SCAN_BYTES,
} from "./scanner";
import type { ScanMatch } from "./scanner";
import { checkEnvExposure } from "./env-shield";
import { extractReadTargets, expandPaths } from "./bash-reads";
import { CredsSession } from "./session";
import {
  formatConfirmMessage,
  formatInputConfirmMessage,
  formatMatchOverflow,
  formatCompactLabels,
} from "./formatters";
import {
  createSentinelPrompt,
  formatPromptTitle,
  runPromptLifecycle,
  type SentinelPrompt,
} from "./prompt";

// ── Types ────────────────────────────────────────────────────────────────

type CredsFeature = "outputScanner" | "envShield" | "inputScanner";

interface CredsBlockedEvent {
  feature: CredsFeature;
  toolName: string;
  input: Record<string, unknown>;
  reason: string;
  userDenied?: boolean;
}

interface CredsDangerousEvent {
  feature: CredsFeature;
  toolName: string;
  input: Record<string, unknown>;
  description: string;
  labels?: string[];
}

// ── Dependencies interface ───────────────────────────────────────────────

export interface SentinelCredsDeps {
  promptWaitTracker: PromptWaitTracker;
  getConfig: (cwd?: string) => Record<string, unknown>;
}

// ── Audit helpers ────────────────────────────────────────────────────────

function hashInput(input: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex").slice(0, 16);
}

function appendAudit(
  config: SentinelCredsConfig,
  kind: string,
  event: CredsDangerousEvent | CredsBlockedEvent,
  decision: string,
): void {
  try {
    const record = {
      ts: new Date().toISOString(),
      kind,
      decision,
      feature: event.feature,
      toolName: event.toolName,
      inputHash: hashInput(event.input),
      labels: "labels" in event ? event.labels : undefined,
      description: "description" in event ? event.description : undefined,
      reason: "reason" in event ? event.reason : undefined,
    };
    mkdirSync(dirname(config.auditLogPath), { recursive: true });
    appendFileSync(config.auditLogPath, JSON.stringify(record) + "\n", "utf-8");
  } catch { /* best-effort */ }
}

function auditDecision(
  config: SentinelCredsConfig,
  feature: CredsFeature,
  toolName: string,
  input: Record<string, unknown>,
  decision: string,
  description: string,
): void {
  appendAudit(config, "decision", { feature, toolName, input, description }, decision);
}

function emitDangerous(
  pi: ExtensionAPI,
  config: SentinelCredsConfig,
  event: CredsDangerousEvent,
): void {
  appendAudit(config, "dangerous", event, "warn");
  try { pi.events?.emit?.("sentinel:dangerous", event); } catch { /* best-effort */ }
}

function blockToolCall(
  pi: ExtensionAPI,
  config: SentinelCredsConfig,
  event: CredsBlockedEvent,
): { block: true; reason: string } {
  appendAudit(config, "blocked", event, event.userDenied ? "deny" : "block");
  try { pi.events?.emit?.("sentinel:blocked", event); } catch { /* best-effort */ }
  return { block: true, reason: event.reason };
}

// ── File scanning ────────────────────────────────────────────────────────

async function scanFile(absolutePath: string, session: CredsSession): Promise<ScanMatch[]> {
  try {
    const fileStat = statSync(absolutePath);
    const cached = session.getCachedScan(absolutePath, fileStat.mtimeMs);
    if (cached) return cached.matches;

    if (fileStat.size > MAX_SCAN_BYTES) return [];
    if (!fileStat.isFile()) return [];

    const { readFile } = await import("node:fs/promises");
    const content = await readFile(absolutePath, "utf-8");

    if (isBinaryContent(content)) {
      session.cacheScan(absolutePath, fileStat.mtimeMs, { hasSecrets: false, matches: [] });
      return [];
    }

    const result = await scanPathForSecrets(absolutePath, content);
    if (!result) return [];

    session.cacheScan(absolutePath, fileStat.mtimeMs, result);
    return result.matches;
  } catch {
    return [];
  }
}

// ── Main registration ────────────────────────────────────────────────────

const MAX_CONFIRM_MATCHES = 5;

function getAgentDir(): string {
  const envDir = process.env.PI_CODING_AGENT_DIR;
  if (!envDir) return join(homedir(), ".pi", "agent");
  if (envDir === "~") return homedir();
  if (envDir.startsWith("~/")) return join(homedir(), envDir.slice(2));
  return envDir;
}

export function registerSentinelCreds(pi: ExtensionAPI, deps: SentinelCredsDeps): void {
  let config = loadSentinelCredsConfig(deps.getConfig(process.cwd()) as { sentinelCreds?: Partial<SentinelCredsConfig> });
  if (!config.enabled) return;

  const session = new CredsSession(process.cwd(), config);
  const { promptWaitTracker } = deps;

  // ── Prompt wrapper using shared tracker ────────────────────────────────

  async function selectWithPromptWait(
    ctx: {
      hasUI: boolean;
      cwd?: string;
      ui: {
        select(title: string, options: string[]): Promise<string | undefined>;
        setStatus(key: string, value: string | undefined): void;
      };
    },
    waitMessage: string,
    prompt: SentinelPrompt,
  ): Promise<string | undefined> {
    const events = {
      emit(channel: string, payload: unknown): void {
        pi.events?.emit?.(channel, payload);
      },
    };

    return runPromptLifecycle(events, prompt, async () => {
      const token = promptWaitTracker.begin(ctx, waitMessage);
      try {
        return await ctx.ui.select(
          formatPromptTitle(prompt),
          prompt.options.map((option) => option.label),
        );
      } finally {
        promptWaitTracker.end(ctx, token);
      }
    });
  }

  // ── Session reset ──────────────────────────────────────────────────────

  function persistReadAllowance(
    scope: PersistentApprovalScope,
    cwd: string | undefined,
    absolutePath: string,
    reason: string,
  ): void {
    session.addToReadWhitelist(absolutePath, reason);
    persistSentinelReadAllowedPathToConfig(
      getScopedConfigPath(getAgentDir(), cwd ?? null, scope),
      absolutePath,
    );
  }

  pi.on("session_start", async (_event, ctx) => {
    config = loadSentinelCredsConfig(deps.getConfig(ctx.cwd) as { sentinelCreds?: Partial<SentinelCredsConfig> });
    session.reset(config);
    if (ctx?.hasUI) {
      promptWaitTracker.clear(ctx);
    }
  });

  // ── Invalidate scan cache on file modifications ────────────────────────

  pi.events?.on?.("context-guard:file-modified", (data: unknown) => {
    const event = data as { path?: string } | undefined;
    if (event?.path) {
      session.invalidateScanCache(resolve(event.path));
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // Guard 0: Intercept user input — confirm pasted credentials
  // ════════════════════════════════════════════════════════════════════════

  pi.on("input", async (event, ctx) => {
    if (!event.text?.trim()) return { action: "continue" };

    const result = await scanContentForSecrets(event.text);
    if (!result.hasSecrets) return { action: "continue" };

    emitDangerous(pi, config, {
      feature: "inputScanner",
      toolName: "input",
      input: { source: event.source, textHash: createHash("sha256").update(event.text).digest("hex").slice(0, 16) },
      description: `User message contains ${result.matches.length} potential credential(s).`,
      labels: result.matches.map((m) => m.label),
    });

    if (ctx.hasUI) {
      const choice = await selectWithPromptWait(
        ctx,
        "Waiting for credential-paste approval",
        createSentinelPrompt({
          header: "Credential paste",
          question: "Paste this message anyway?",
          details: formatInputConfirmMessage(result.matches),
          options: [
            {
              label: "Paste anyway",
              description: "Continue; credential-like values may enter conversation history.",
            },
            {
              label: "Cancel",
              description: "Discard message and keep credentials out of conversation history.",
            },
          ],
        }),
      );

      if (choice === "Paste anyway") {
        auditDecision(config, "inputScanner", "input", { source: event.source }, "paste_anyway", "User confirmed pasted credential-like message; previews were truncated.");
        return { action: "continue" };
      }

      appendAudit(config, "blocked", {
        feature: "inputScanner",
        toolName: "input",
        input: { source: event.source },
        reason: "User cancelled message containing potential credentials.",
        userDenied: true,
      }, "cancel");
      return { action: "handled" };
    }

    // No UI — apply headlessMode policy
    if (config.headlessMode === "allow") return { action: "continue" };
    if (config.headlessMode === "warn") {
      emitDangerous(pi, config, {
        feature: "inputScanner",
        toolName: "input",
        input: { source: event.source },
        description: `User message contains ${result.matches.length} potential credential(s) but headless mode is 'warn'.`,
        labels: result.matches.map((m) => m.label),
      });
      return { action: "continue" };
    }

    appendAudit(config, "blocked", {
      feature: "inputScanner",
      toolName: "input",
      input: { source: event.source },
      reason: `Blocked message containing ${result.matches.length} potential credential(s).`,
      userDenied: false,
    }, "block");
    return { action: "handled" };
  });

  // ════════════════════════════════════════════════════════════════════════
  // Guard 1: Intercept `read` tool calls — scan for secrets
  // ════════════════════════════════════════════════════════════════════════

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "read" && event.toolName !== "read_file") return;
    const rawPath = event.input?.path;
    if (!rawPath || typeof rawPath !== "string") return;

    const absolutePath = resolve(
      ctx.cwd,
      rawPath.startsWith("@") ? rawPath.slice(1) : rawPath,
    );

    if (session.isReadWhitelisted(absolutePath)) return;

    const matches = await scanFile(absolutePath, session);
    if (matches.length === 0) return;

    emitDangerous(pi, config, {
      feature: "outputScanner",
      toolName: "read",
      input: event.input as Record<string, unknown>,
      description: `File contains ${matches.length} potential secret(s).`,
      labels: matches.map((m) => m.label),
    });

    if (ctx.hasUI) {
      const choice = await selectWithPromptWait(
        ctx,
        "Waiting for secret-read approval",
        createSentinelPrompt({
          header: "Secret read",
          question: "Allow reading this file?",
          details: `Secret detected\n\n${formatConfirmMessage(matches)}`,
          options: [
            {
              label: "Allow once",
              description: "Read once; output follows configured result-scanning policy.",
            },
            ...(ctx.cwd
              ? [{
                  label: "Allow for this workspace",
                  description: "Remember this path for this workspace; output follows configured result-scanning policy.",
                }]
              : []),
            {
              label: "Allow globally",
              description: "Remember this path globally; output follows configured result-scanning policy.",
            },
            {
              label: "Deny",
              description: "Block this read.",
            },
          ],
        }),
      );

      if (choice === "Allow once") {
        session.allowReadResult(absolutePath);
        auditDecision(config, "outputScanner", "read", event.input as Record<string, unknown>, "allow_once_redacted", "User allowed one read; output redaction remains enabled.");
        return;
      }
      if (choice === "Allow for this workspace") {
        persistReadAllowance(
          "workspace",
          ctx.cwd,
          absolutePath,
          "user selected Allow for this workspace",
        );
        auditDecision(config, "outputScanner", "read", event.input as Record<string, unknown>, "allow_workspace_redacted", "User persisted file allowance in workspace config; output redaction remains enabled.");
        return;
      }
      if (choice === "Allow globally") {
        persistReadAllowance(
          "global",
          ctx.cwd,
          absolutePath,
          "user selected Allow globally",
        );
        auditDecision(config, "outputScanner", "read", event.input as Record<string, unknown>, "allow_global_redacted", "User persisted file allowance in global config; output redaction remains enabled.");
        return;
      }
    }

    // No UI — apply headlessMode policy
    if (!ctx.hasUI && config.headlessMode === "allow") return;
    if (!ctx.hasUI && config.headlessMode === "warn") {
      emitDangerous(pi, config, {
        feature: "outputScanner",
        toolName: "read",
        input: event.input as Record<string, unknown>,
        description: `File contains ${matches.length} potential secret(s) but headless mode is 'warn'.`,
        labels: matches.map((m) => m.label),
      });
      return;
    }

    const reason =
      `[sentinel-creds] Blocked: file contains ${matches.length} potential secret(s). ` +
      `Types: ${formatCompactLabels(matches)}.`;
    return blockToolCall(pi, config, {
      feature: "outputScanner",
      toolName: "read",
      input: event.input as Record<string, unknown>,
      reason,
      userDenied: ctx.hasUI,
    });
  });

  // ════════════════════════════════════════════════════════════════════════
  // Guard 2: Intercept `bash` commands that read files or dump env
  // ════════════════════════════════════════════════════════════════════════

  if (config.scanBashReads || config.envShield) {
    pi.on("tool_call", async (event, ctx) => {
      if (event.toolName !== "bash") return;
      const command = (event.input?.command ?? "") as string;

      // --- Env-shield ---
      if (config.envShield) {
        const envReason = checkEnvExposure(command, config.safeEnvPrefixes);
        if (envReason) {
          emitDangerous(pi, config, {
            feature: "envShield",
            toolName: "bash",
            input: event.input as Record<string, unknown>,
            description: envReason,
          });

          if (ctx.hasUI) {
            const choice = await selectWithPromptWait(
              ctx,
              "Waiting for env exposure approval",
              createSentinelPrompt({
                header: "Env exposure",
                question: "Allow this command to expose environment variables?",
                details: envReason,
                options: [
                  {
                    label: "Allow once",
                    description: "Run this command once; output follows configured result-scanning policy.",
                  },
                  {
                    label: "Deny",
                    description: "Block this command.",
                  },
                ],
              }),
            );
            if (choice === "Allow once") {
              auditDecision(config, "envShield", "bash", event.input as Record<string, unknown>, "allow_once", "User allowed env exposure command once.");
            } else {
              return blockToolCall(pi, config, {
                feature: "envShield",
                toolName: "bash",
                input: event.input as Record<string, unknown>,
                reason: `[sentinel-creds] Blocked: ${envReason}`,
                userDenied: true,
              });
            }
          } else {
            if (config.headlessMode === "allow") {
              // silently allow
            } else if (config.headlessMode === "warn") {
              emitDangerous(pi, config, {
                feature: "envShield",
                toolName: "bash",
                input: event.input as Record<string, unknown>,
                description: `${envReason} (headless mode is 'warn')`,
              });
            } else {
              return blockToolCall(pi, config, {
                feature: "envShield",
                toolName: "bash",
                input: event.input as Record<string, unknown>,
                reason: `[sentinel-creds] Blocked: ${envReason}`,
                userDenied: false,
              });
            }
          }
        }
      }

      // --- File-read scanning ---
      if (!config.scanBashReads) return;

      const targets = extractReadTargets(command);
      if (targets.length === 0) return;

      const expandedTargets = (
        await Promise.all(
          targets.map(async (target) =>
            (await expandPaths(ctx.cwd, target)).map((absolutePath) => ({ target, absolutePath })),
          ),
        )
      ).flat().slice(0, 100);

      const scanResults = await Promise.all(
        expandedTargets
          .filter(({ absolutePath }) => !session.isReadWhitelisted(absolutePath))
          .map(async ({ target, absolutePath }) => ({
            path: target,
            absolutePath,
            matches: await scanFile(absolutePath, session),
          })),
      );
      const allMatches = scanResults.filter((entry) => entry.matches.length > 0);
      if (allMatches.length === 0) return;

      emitDangerous(pi, config, {
        feature: "outputScanner",
        toolName: "bash",
        input: event.input as Record<string, unknown>,
        description: "Bash command reads file(s) that may contain secrets.",
        labels: allMatches.flatMap((entry) => entry.matches.map((m) => m.label)),
      });

      const flattenedMatches = allMatches.flatMap(({ path, matches }) =>
        matches.map((match) => ({ path, match })),
      );
      const shownMatches = flattenedMatches.slice(0, MAX_CONFIRM_MATCHES);
      const message = [
        ...shownMatches.map(
          ({ path, match }) =>
            `  - ${match.label} in ${path} (line ${match.line}): ${match.snippet}`,
        ),
        ...formatMatchOverflow(flattenedMatches.length, shownMatches.length),
      ].join("\n");

      if (ctx.hasUI) {
        const choice = await selectWithPromptWait(
          ctx,
          "Waiting for bash secret approval",
          createSentinelPrompt({
            header: "Bash secret",
            question: "Allow this command to read secret-like files?",
            details: `Command reads file(s) that may contain secrets:\n${message}`,
            options: [
              {
                label: "Allow once",
                description: "Run this command once; output follows configured result-scanning policy.",
              },
              ...(ctx.cwd
                ? [{
                    label: "Allow for this workspace",
                    description: "Remember these paths for this workspace; output follows configured result-scanning policy.",
                  }]
                : []),
              {
                label: "Allow globally",
                description: "Remember these paths globally; output follows configured result-scanning policy.",
              },
              {
                label: "Deny",
                description: "Block this command.",
              },
            ],
          }),
        );

        if (choice === "Allow once") {
          session.allowBashResult(command);
          auditDecision(config, "outputScanner", "bash", event.input as Record<string, unknown>, "allow_once_redacted", "User allowed bash command once; output redaction remains enabled.");
          return;
        }
        if (choice === "Allow for this workspace") {
          for (const { absolutePath } of allMatches) {
            persistReadAllowance(
              "workspace",
              ctx.cwd,
              absolutePath,
              "user selected Allow for this workspace",
            );
          }
          auditDecision(config, "outputScanner", "bash", event.input as Record<string, unknown>, "allow_workspace_redacted", "User persisted bash target file allowances in workspace config; output redaction remains enabled.");
          return;
        }
        if (choice === "Allow globally") {
          for (const { absolutePath } of allMatches) {
            persistReadAllowance(
              "global",
              ctx.cwd,
              absolutePath,
              "user selected Allow globally",
            );
          }
          auditDecision(config, "outputScanner", "bash", event.input as Record<string, unknown>, "allow_global_redacted", "User persisted bash target file allowances in global config; output redaction remains enabled.");
          return;
        }
      } else {
        if (config.headlessMode === "allow") return;
        if (config.headlessMode === "warn") {
          emitDangerous(pi, config, {
            feature: "outputScanner",
            toolName: "bash",
            input: event.input as Record<string, unknown>,
            description: `Bash command reads file(s) with ${flattenedMatches.length} potential secret(s) but headless mode is 'warn'.`,
            labels: allMatches.flatMap((entry) => entry.matches.map((m) => m.label)),
          });
          return;
        }
      }

      const totalMatches = flattenedMatches.length;
      const reason = `[sentinel-creds] Blocked: bash command reads file(s) with ${totalMatches} potential secret(s).`;
      return blockToolCall(pi, config, {
        feature: "outputScanner",
        toolName: "bash",
        input: event.input as Record<string, unknown>,
        reason,
        userDenied: ctx.hasUI,
      });
    });
  }

  // ════════════════════════════════════════════════════════════════════════
  // Guard 3: Scan `grep` tool calls for secret files
  // ════════════════════════════════════════════════════════════════════════

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "grep" && event.toolName !== "search") return;

    const inputPath = event.input?.path as string | undefined;
    if (!inputPath) return;

    const pattern = (event.input?.pattern ?? "") as string;
    const secretPattern = /(?:secret|password|token|api_key|apikey|api-key|credential|auth_token|auth_key|auth_secret|auth_pass)/i;
    if (!secretPattern.test(pattern)) return;

    emitDangerous(pi, config, {
      feature: "outputScanner",
      toolName: event.toolName,
      input: event.input as Record<string, unknown>,
      description: `Search pattern may match secret values in results.`,
      labels: ["Secret Pattern Search"],
    });

    if (ctx.hasUI) {
      const choice = await selectWithPromptWait(
        ctx,
        "Waiting for secret-search approval",
        createSentinelPrompt({
          header: "Secret search",
          question: "Allow this search?",
          details: `Pattern "${pattern}" may expose secret values in search results.`,
          options: [
            {
              label: "Allow once",
              description: "Run this search once; matching output follows configured result-scanning policy.",
            },
            {
              label: "Deny",
              description: "Block this search.",
            },
          ],
        }),
      );
      if (choice === "Allow once") return;
      return blockToolCall(pi, config, {
        feature: "outputScanner",
        toolName: event.toolName,
        input: event.input as Record<string, unknown>,
        reason: "[sentinel-creds] Blocked: search pattern may expose secret values.",
        userDenied: true,
      });
    } else {
      if (config.headlessMode === "allow") return;
      if (config.headlessMode === "warn") {
        emitDangerous(pi, config, {
          feature: "outputScanner",
          toolName: event.toolName,
          input: event.input as Record<string, unknown>,
          description: `Search pattern "${pattern}" may expose secret values but headless mode is 'warn'.`,
          labels: ["Secret Pattern Search"],
        });
        return;
      }
      return blockToolCall(pi, config, {
        feature: "outputScanner",
        toolName: event.toolName,
        input: event.input as Record<string, unknown>,
        reason: `[sentinel-creds] Blocked: search pattern "${pattern}" may expose secret values.`,
        userDenied: false,
      });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // Guard 4: Result scanning — redact secrets from tool output
  // ════════════════════════════════════════════════════════════════════════

  if (config.resultScanning) {
    pi.on("tool_result" as never, (async (event: {
      toolName: string;
      input?: Record<string, unknown>;
      result?: unknown;
    }) => {
      const toolName = event.toolName;
      if (toolName !== "read" && toolName !== "bash" && toolName !== "grep" && toolName !== "search") {
        return undefined;
      }

      const content = event.result as string;
      if (!content || typeof content !== "string") return undefined;

      const runtimeConfig = loadSentinelCredsConfig(deps.getConfig() as { sentinelCreds?: Partial<SentinelCredsConfig> });

      if (toolName === "read") {
        const rawPath = event.input?.path;
        if (rawPath && typeof rawPath === "string") {
          const absolutePath = session.resolvePath(rawPath);
          const wasAllowed = session.isReadResultAllowed(absolutePath);
          session.consumeReadResultAllowance(absolutePath);
          if (wasAllowed && runtimeConfig.allowRawReveal) return undefined;
        }
      }

      if (toolName === "bash") {
        const command = (event.input?.command ?? "") as string;
        const wasAllowed = command ? session.isBashResultAllowed(command) : false;
        if (command) session.consumeBashResultAllowance(command);
        if (wasAllowed && runtimeConfig.allowRawReveal) return undefined;
      }

      const result = await scanContentForSecrets(content);
      if (!result.hasSecrets) return undefined;

      const redacted = redactSecrets(content, result.matches);
      if (redacted === content) return undefined;

      emitDangerous(pi, config, {
        feature: "outputScanner",
        toolName,
        input: { redactedSecrets: true },
        description: `Redacted ${result.matches.length} secret(s) from tool output.`,
        labels: [...new Set(result.matches.map((m) => m.label))],
      });

      return { result: redacted };
    }) as never);
  }
}
