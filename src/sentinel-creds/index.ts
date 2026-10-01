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
import { appendFileSync, lstatSync, mkdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { createHash } from "node:crypto";

import type { PromptWaitTracker } from "../prompt-state";
import type { YoloAutoEvaluator } from "../yolo-auto-evaluator";
import { isPathWithinCanonicalWorkingDirectory } from "../path-utils";
import { isSensitivePath } from "../yolo-auto-sensitive-paths";
import {
  getScopedConfigPath,
  persistSentinelReadAllowedPathToConfig,
  type PersistentApprovalScope,
} from "../scoped-config";
import { allMatchesLowTier } from "./credential-tier.js";
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
  getPermissionConfig?: (cwd?: string) => {
    mode?: "manual" | "yolo" | "yolo-auto";
  };
  yoloAutoEvaluator?: Pick<YoloAutoEvaluator, "evaluate">;
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

function isWorkspaceEnvRead(absolutePath: string, cwd: string | undefined): boolean {
  return basename(absolutePath).startsWith(".env")
    && isCanonicalWorkspaceRegularFile(absolutePath, cwd);
}

function isCanonicalWorkspaceRegularFile(absolutePath: string, cwd: string | undefined): boolean {
  if (!cwd) return false;
  try {
    const fileStat = lstatSync(absolutePath);
    return fileStat.isFile()
      && !fileStat.isSymbolicLink()
      && isPathWithinCanonicalWorkingDirectory(absolutePath, cwd);
  } catch {
    return false;
  }
}

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
  const redactionNote = () => (config.resultScanning ? "output is redacted." : "output is NOT redacted.");
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
    session.reset(config, ctx.cwd);
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

    let yoloAutoSecretReadAttempted = false;
    let yoloAutoSecretReadReason = "model_review_required";
    const permissionConfig = deps.getPermissionConfig?.(ctx.cwd);
    const yoloAutoEvaluator = deps.yoloAutoEvaluator;
    const hasStableToolCallId = typeof event.toolCallId === "string" && event.toolCallId.length > 0;
    const yoloAutoSecretReadCandidate =
      yoloAutoEvaluator !== undefined
      && permissionConfig?.mode === "yolo-auto"
      && config.resultScanning
      && event.toolName === "read"
      && hasStableToolCallId
      && allMatchesLowTier(matches)
      && isCanonicalWorkspaceRegularFile(absolutePath, ctx.cwd);
    if (yoloAutoSecretReadCandidate) {
      const evaluation = await yoloAutoEvaluator.evaluate({
        flow: "secret_read",
        candidate: true,
        enabled: true,
        permissionState: "ask",
        source: "tool_call",
        eligible: true,
        forcedPrompt: false,
        workspaceLocal: true,
        operation: "read",
        toolName: "read",
        hardRuleHit: isSensitivePath(absolutePath, homedir()),
        toolCallIdPresent: true,
        toolCallId: event.toolCallId,
      });
      if (evaluation.action === "allow") {
        auditDecision(
          config,
          "outputScanner",
          "read",
          { toolName: "read", operation: "read" },
          "allow_model_redacted",
          "Model allowed one eligible read; output redaction remains enabled.",
        );
        return;
      }
      yoloAutoSecretReadAttempted = evaluation.attempted;
      yoloAutoSecretReadReason = evaluation.reason;
    }

    if (
      config.resultScanning
      && event.toolName === "read"
      && isWorkspaceEnvRead(absolutePath, ctx.cwd)
    ) {
      auditDecision(
        config,
        "outputScanner",
        "read",
        { toolName: "read", operation: "read", redactedSecrets: true },
        "allow_workspace_env_redacted",
        "Allowed canonical workspace .env* read; result scanning remains mandatory.",
      );
      return;
    }

    const autoApprovalNote = permissionConfig?.mode !== "yolo-auto"
      ? ""
      : !allMatchesLowTier(matches)
        ? "\n\nAuto-approval skipped: high-sensitivity credential type present."
        : yoloAutoSecretReadAttempted
          ? `\n\nAuto-approval declined by model (${yoloAutoSecretReadReason}).`
          : "";

    if (ctx.hasUI) {
      const choice = await selectWithPromptWait(
        ctx,
        "Waiting for secret-read approval",
        createSentinelPrompt({
          header: "Secret read",
          question: "Allow reading this file?",
          details: `Secret detected\n\n${formatConfirmMessage(matches)}${autoApprovalNote}`,
          options: [
            {
              label: "Allow once",
              description: `Read once; ${redactionNote()}`,
            },
            ...(ctx.cwd
              ? [{
                  label: "Allow for this workspace",
                  description: `Remember this path for this workspace; ${redactionNote()}`,
                }]
              : []),
            {
              label: "Allow globally",
              description: `Remember this path globally; ${redactionNote()}`,
            },
            {
              label: "Deny",
              description: "Block this read.",
            },
          ],
        }),
      );

      if (choice === "Allow once") {
        session.allowReadResult(event.toolCallId, absolutePath);
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

    // Model-routed secret reads fail closed in headless mode after an attempt.
    if (!ctx.hasUI && yoloAutoSecretReadAttempted) {
      return blockToolCall(pi, config, {
        feature: "outputScanner",
        toolName: "read",
        input: { toolName: "read", operation: "read" },
        reason: `[sentinel-creds] Blocked: yolo-auto secret-read review did not allow access (${yoloAutoSecretReadReason}).`,
        userDenied: false,
      });
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
                    description: `Run this command once; ${redactionNote()}`,
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
                description: `Run this command once; ${redactionNote()}`,
              },
              ...(ctx.cwd
                ? [{
                    label: "Allow for this workspace",
                    description: `Remember these paths for this workspace; ${redactionNote()}`,
                  }]
                : []),
              {
                label: "Allow globally",
                description: `Remember these paths globally; ${redactionNote()}`,
              },
              {
                label: "Deny",
                description: "Block this command.",
              },
            ],
          }),
        );

        if (choice === "Allow once") {
          session.allowBashResult(event.toolCallId, command);
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

    // D15: model may approve only a single workspace file whose secrets are all low-tier.
    const grepEvaluator = deps.yoloAutoEvaluator;
    const grepPath = resolve(ctx.cwd ?? process.cwd(), inputPath);
    if (
      grepEvaluator !== undefined
      && deps.getPermissionConfig?.(ctx.cwd)?.mode === "yolo-auto"
      && config.resultScanning
      && typeof event.toolCallId === "string" && event.toolCallId.length > 0
      && isCanonicalWorkspaceRegularFile(grepPath, ctx.cwd)
      && allMatchesLowTier(await scanFile(grepPath, session))
    ) {
      const evaluation = await grepEvaluator.evaluate({
        flow: "secret_read",
        candidate: true,
        enabled: true,
        permissionState: "ask",
        source: "tool_call",
        eligible: true,
        forcedPrompt: false,
        workspaceLocal: true,
        operation: "read",
        toolName: "grep",
        hardRuleHit: isSensitivePath(grepPath, homedir()),
        toolCallIdPresent: true,
        toolCallId: event.toolCallId,
      });
      if (evaluation.action === "allow") {
        auditDecision(
          config,
          "outputScanner",
          event.toolName,
          { toolName: event.toolName, operation: "read" },
          "allow_model_redacted",
          "Model allowed one low-tier secret search; output redaction remains enabled.",
        );
        return;
      }
      // Model-routed secret searches fail closed in headless mode after an attempt (matches Guard 1).
      if (!ctx.hasUI && evaluation.attempted) {
        return blockToolCall(pi, config, {
          feature: "outputScanner",
          toolName: event.toolName,
          input: { toolName: event.toolName, operation: "read" },
          reason: `[sentinel-creds] Blocked: yolo-auto secret-search review did not allow access (${evaluation.reason}).`,
          userDenied: false,
        });
      }
    }

    if (ctx.hasUI) {
      const choice = await selectWithPromptWait(
        ctx,
        "Waiting for secret-search approval",
        createSentinelPrompt({
          header: "Secret search",
          question: "Allow this search?",
          details: `Pattern "${pattern}" in ${inputPath} may expose secret values in search results.`,
          options: [
            {
              label: "Allow once",
              description: `Run this search once; matching ${redactionNote()}`,
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

  pi.on("tool_result", async (event, ctx) => {
    const { toolName } = event;
    if (toolName !== "read" && toolName !== "bash" && toolName !== "grep" && toolName !== "search") {
      return undefined;
    }

    const runtimeConfig = loadSentinelCredsConfig(deps.getConfig(ctx.cwd) as { sentinelCreds?: Partial<SentinelCredsConfig> });
    if (!runtimeConfig.resultScanning) return undefined;

    if (toolName === "read") {
      const rawPath = event.input?.path;
      if (rawPath && typeof rawPath === "string") {
        const absolutePath = session.resolvePath(rawPath);
        const wasAllowed = session.isReadResultAllowed(event.toolCallId, absolutePath);
        session.consumeReadResultAllowance(event.toolCallId, absolutePath);
        if (wasAllowed && runtimeConfig.allowRawReveal) return undefined;
      }
    }

    if (toolName === "bash") {
      const command = typeof event.input?.command === "string" ? event.input.command : "";
      const wasAllowed = command && session.isBashResultAllowed(event.toolCallId, command);
      if (command) session.consumeBashResultAllowance(event.toolCallId, command);
      if (wasAllowed && runtimeConfig.allowRawReveal) return undefined;
    }

    const scannedBlocks = await Promise.all(
      event.content.map(async (block) => {
        if (block.type !== "text") return { block };
        if (Buffer.byteLength(block.text, "utf8") > MAX_SCAN_BYTES) {
          return { block, scanUnavailable: true };
        }
        try {
          return { block, result: await scanContentForSecrets(block.text) };
        } catch {
          return { block, scanUnavailable: true };
        }
      }),
    );

    if (scannedBlocks.some(({ scanUnavailable }) => scanUnavailable)) {
      const content = scannedBlocks.map(({ block, result, scanUnavailable }) => {
        if (scanUnavailable && block.type === "text") {
          return { ...block, text: "[sentinel-creds] Output withheld because secret scanning was unavailable." };
        }
        if (block.type !== "text" || !result?.hasSecrets) return block;
        const redacted = redactSecrets(block.text, result.matches);
        return redacted === block.text ? block : { ...block, text: redacted };
      });
      emitDangerous(pi, config, {
        feature: "outputScanner",
        toolName,
        input: { redactedSecrets: true },
        description: "Withheld tool output because secret scanning was unavailable.",
        labels: ["Secret scan unavailable"],
      });
      return { content };
    }

    const matches = scannedBlocks.flatMap(({ result }) => result?.matches ?? []);
    if (matches.length === 0) return undefined;

    const content = scannedBlocks.map(({ block, result }) => {
      if (block.type !== "text" || !result?.hasSecrets) return block;
      const redacted = redactSecrets(block.text, result.matches);
      return redacted === block.text ? block : { ...block, text: redacted };
    });

    emitDangerous(pi, config, {
      feature: "outputScanner",
      toolName,
      input: { redactedSecrets: true },
      description: `Redacted ${matches.length} secret(s) from tool output.`,
      labels: [...new Set(matches.map((match) => match.label))],
    });

    return { content };
  });
}
