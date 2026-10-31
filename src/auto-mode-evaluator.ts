import { featuresFromHeads, type EvaluationRow } from "./auto-mode-decision-store";
import { FUSION_VERSION, fuseWithNeighbours, type FusionDecision } from "./auto-mode-fusion";
import type { NeighbourQuery, NeighbourSummary } from "./auto-mode-neighbours";
import type { ScorerResult } from "./auto-mode-scorer";
import { createHash, randomUUID } from "node:crypto";

import { decideAutoMode, AUTO_MODE_POLICY_THRESHOLDS } from "./auto-mode-policy";
import type { AutoModeHeads } from "./auto-mode-policy";
import { MODEL_REVISION } from "./auto-mode-build";
import type { PermissionState } from "./types";
import { buildAutoModeText, AutoModeBuildMismatchError } from "./auto-mode-client";
import type {
  AutoModeClient,
  AutoModeClientResult,
  AutoModeFailureReason,
} from "./auto-mode-client";

type EvaluationFlow = "permission" | "secret_read";
type EvaluationOperation = "read" | "list" | "write" | "edit" | "exec";
type EvaluationSkipReason =
  | "not_candidate"
  | "result_scanning_disabled"
  | "unsupported_tool"
  | "unstable_tool_call_id"
  | "not_workspace_local"
  | "too_many_units"
  | "unit_too_long";

interface FusionTelemetry {
  modelPolicyReason: string;
  summary: NeighbourSummary;
  scorer?: ScorerResult;
}

export interface AutoModeEvaluationRequest {
  flow: EvaluationFlow;
  candidate: boolean;
  enabled: boolean;
  permissionState: PermissionState;
  source: string;
  eligible: boolean;
  forcedPrompt: boolean;
  workspaceLocal: boolean;
  operation: EvaluationOperation;
  toolName: string;
  workspaceRelativePath?: string;
  text?: string;
  truncated?: boolean;
  /** Redacted inner Bash commands; each is classified on its own so none hides behind the 256-token window. */
  units?: string[];
  /** The inner Bash commands cannot all be read statically. */
  opaque?: boolean;
  hardRuleHit: boolean;
  sandboxed?: boolean;
  toolCallIdPresent: boolean;
  /** Opaque tool-call id for joining evaluations to human decisions. */
  toolCallId?: string;
  /** Decision-store scope (hashed workspace) and coarse pattern key. */
  scope?: string;
  patternKey?: string;
  skipReason?: EvaluationSkipReason;
}

export interface AutoModeEvaluationDecision {
  action: "allow" | "prompt";
  reason: string;
  candidate: boolean;
  attempted: boolean;
  evaluationId: string;
  audit: boolean;
}

export interface AutoModeCalibrationRecord {
  evaluationId: string;
  ts: string;
  modelRev: string;
  toolName: string;
  operation: string;
  textLength: number;
  textSha256: string;
  truncated: boolean;
  heads: AutoModeHeads | null;
  decision: "allow" | "prompt";
  reason: string;
  hardRuleHit: boolean;
  audit: boolean;
  latencyMs: number;
}

export interface AutoModeEvaluatorDeps {
  client: Pick<AutoModeClient, "evaluate">;
  waitForStartup?: () => Promise<void>;
  writeReviewLog?: (event: string, details: Record<string, unknown>) => void;
  writeDebugLog?: (event: string, details: Record<string, unknown>) => void;
  writeCalibrationLog?: (record: AutoModeCalibrationRecord) => void | Promise<void>;
  recordEvaluation?: (row: EvaluationRow) => void;
  summarizeNeighbours?: (query: NeighbourQuery) => NeighbourSummary;
  /** Workspace scorer; undefined unless two-class history is large enough. */
  scoreRequest?: (query: NeighbourQuery) => ScorerResult | undefined;
  random?: () => number;
  now?: () => number;
}

const MODEL_AUDIT_RATE = 0.05;
const HISTORY_AUDIT_RATE = 0.2;
const MAX_UNITS = 8;
/* A token covers at least one UTF-8 byte, so this keeps a unit and its prefix inside the 256-token window. */
const MAX_UNIT_BYTES = 200;

interface UnitOutcome {
  result: Extract<AutoModeClientResult, { status: "complete" }>;
  policy: FusionDecision;
}

/* Malformed heads rank as least benign; the policy already turned them into a prompt. */
const benignOf = (outcome: UnitOutcome): number =>
  (outcome.result.heads as Partial<AutoModeHeads>).threat?.benign ?? -1;

/** Allow only when every input allows; the least benign blocking input decides. */
function decidingOutcome(outcomes: UnitOutcome[]): { deciding: UnitOutcome; blockingCount: number } {
  const blocking = outcomes.filter((outcome) => outcome.policy.action !== "allow");
  const deciding = (blocking.length ? blocking : outcomes).reduce((worst, next) =>
    benignOf(next) < benignOf(worst) ? next : worst);
  return { deciding, blockingCount: blocking.length };
}

function unitCapReason(units: string[] | undefined): "too_many_units" | "unit_too_long" | undefined {
  if (!units) return undefined;
  if (units.length > MAX_UNITS) return "too_many_units";
  return units.some((unit) => Buffer.byteLength(unit) > MAX_UNIT_BYTES) ? "unit_too_long" : undefined;
}

const round2 = (value: number): number => Math.round(value * 100) / 100;

function elapsed(now: () => number, startedAt: number): number {
  return Math.max(0, now() - startedAt);
}

export class AutoModeEvaluator {
  private readonly now: () => number;
  private readonly random: () => number;

  constructor(private readonly deps: AutoModeEvaluatorDeps) {
    this.now = deps.now ?? Date.now;
    this.random = deps.random ?? Math.random;
  }

  async evaluate(request: AutoModeEvaluationRequest): Promise<AutoModeEvaluationDecision> {
    const startedAt = this.now();
    const evaluationId = randomUUID();
    const inputText = request.text ?? buildAutoModeText({
      toolName: request.toolName,
      operation: request.operation,
      ...(request.workspaceRelativePath
        ? { workspaceRelativePath: request.workspaceRelativePath }
        : {}),
    });
    if (!request.candidate) {
      const reason = request.skipReason ?? "not_candidate";
      const decision = {
        action: "prompt" as const,
        reason,
        candidate: false,
        attempted: false,
        evaluationId,
        audit: false,
      };
      await this.writeTelemetry(request, decision, {
        evaluationId,
        disposition: "skipped",
        outcome: "skipped",
        classificationLatencyMs: 0,
        startupLatencyMs: 0,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: reason,
        modelBuildId: null,
      }, inputText);
      return decision;
    }

    const capReason = unitCapReason(request.units);
    if (capReason) {
      const decision = { ...this.promptDecision(evaluationId, capReason), attempted: false };
      await this.writeTelemetry(request, decision, {
        evaluationId,
        disposition: "skipped",
        outcome: "skipped",
        classificationLatencyMs: 0,
        startupLatencyMs: 0,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: capReason,
        modelBuildId: null,
        unitCount: request.units!.length,
      }, inputText);
      return decision;
    }

    let startupLatencyMs = 0;
    if (this.deps.waitForStartup) {
      const startupStartedAt = this.now();
      try {
        await this.deps.waitForStartup();
      } catch (error) {
        const reason = error instanceof AutoModeBuildMismatchError ? "build_mismatch" : "startup_failed";
        const decision = this.promptDecision(evaluationId, reason);
        await this.writeTelemetry(request, decision, {
          evaluationId,
          disposition: "attempted",
          outcome: "prompt",
          classificationLatencyMs: 0,
          startupLatencyMs: elapsed(this.now, startupStartedAt),
          totalLatencyMs: elapsed(this.now, startedAt),
          failureReason: reason,
          modelBuildId: null,
        }, inputText);
        return decision;
      }
      startupLatencyMs = elapsed(this.now, startupStartedAt);
    }

    const texts = this.classificationTexts(request, inputText);
    const classified = await this.classify(request, texts, evaluationId);
    if ("failure" in classified) {
      const { failure } = classified;
      const decision = this.promptDecision(failure.evaluationId, failure.reason);
      await this.writeTelemetry(request, decision, {
        evaluationId: failure.evaluationId,
        disposition: "attempted",
        outcome: "prompt",
        classificationLatencyMs: classified.latencyMs,
        startupLatencyMs,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: failure.reason,
        modelBuildId: null,
      }, inputText);
      return decision;
    }
    const { outcomes, latencyMs: classificationLatencyMs } = classified;

    const { deciding, blockingCount } = decidingOutcome(outcomes);
    const { result, policy: policyDecision } = deciding;
    const resultEvaluationId = result.evaluationId;
    // History may convert one low-confidence input, never a request with several blocking ones.
    const history = blockingCount > 1 ? { policy: policyDecision } : this.applyHistory(request, result.heads, policyDecision);
    const finalPolicy = history.policy;
    const audit = this.isAudited(finalPolicy, policyDecision);
    const decision: AutoModeEvaluationDecision = {
      action: audit ? "prompt" : finalPolicy.action,
      reason: audit ? "audit_sample" : finalPolicy.reason,
      candidate: true,
      attempted: true,
      evaluationId: resultEvaluationId,
      audit,
    };
    this.recordForStore(request, resultEvaluationId, result.heads, policyDecision.action, audit);
    await this.writeTelemetry(request, decision, {
      evaluationId: resultEvaluationId,
      disposition: "attempted",
      outcome: decision.action === "allow" ? "allowed" : "prompt",
      classificationLatencyMs,
      startupLatencyMs,
      totalLatencyMs: elapsed(this.now, startedAt),
      failureReason: null,
      modelBuildId: result.buildId,
      heads: result.heads,
      audit,
      ...(request.units ? { unitCount: texts.length, decidingUnit: outcomes.indexOf(deciding) } : {}),
      ...(history.fusion ? { fusion: history.fusion } : {}),
    }, texts[outcomes.indexOf(deciding)] ?? inputText);
    return decision;
  }

  /** Classify every input in order; the first unavailable result or transport error stops the request. */
  private async classify(
    request: AutoModeEvaluationRequest,
    texts: string[],
    evaluationId: string,
  ): Promise<
    | { outcomes: UnitOutcome[]; latencyMs: number }
    | { failure: { evaluationId: string; reason: AutoModeFailureReason | "transport_failure" }; latencyMs: number }
  > {
    const outcomes: UnitOutcome[] = [];
    let latencyMs = 0;
    for (const text of texts) {
      let result: AutoModeClientResult;
      try {
        result = await this.deps.client.evaluate(text);
      } catch {
        return { failure: { evaluationId, reason: "transport_failure" }, latencyMs };
      }
      latencyMs += result.totalLatencyMs;
      if (result.status === "unavailable") {
        return { failure: { evaluationId: result.evaluationId, reason: result.reason }, latencyMs };
      }
      outcomes.push({
        result,
        policy: decideAutoMode({
          enabled: request.enabled,
          permissionState: request.permissionState,
          source: request.source,
          eligible: request.eligible,
          forcedPrompt: request.forcedPrompt,
          workspaceLocal: request.workspaceLocal,
          hardRuleHit: request.hardRuleHit,
          sandboxed: request.sandboxed ?? false,
          operation: request.operation,
          toolName: request.toolName,
          heads: result.heads,
        }),
      });
    }
    return { outcomes, latencyMs };
  }

  /**
   * The model inputs for one request. Compound Bash commands add every inner command
   * to the whole command: the whole keeps loop and group context, while the parts
   * cover what the 256-token window cuts off.
   */
  private classificationTexts(request: AutoModeEvaluationRequest, inputText: string): string[] {
    if (!request.units?.length) return [inputText];
    const units = request.units.map((command) =>
      buildAutoModeText({ toolName: request.toolName, operation: request.operation, command }));
    return units.length === 1 && units[0] === inputText ? units : [inputText, ...units];
  }

  /** History-driven allows are the learned ones, so they are audited more often to get unbiased labels. */
  private isAudited(final: FusionDecision, model: FusionDecision): boolean {
    if (final.action !== "allow") return false;
    return this.random() < (final.reason !== model.reason ? HISTORY_AUDIT_RATE : MODEL_AUDIT_RATE);
  }

  private promptDecision(
    evaluationId: string,
    reason: AutoModeFailureReason | "startup_failed" | "transport_failure" | EvaluationSkipReason,
  ): AutoModeEvaluationDecision {
    return {
      action: "prompt",
      reason,
      candidate: true,
      attempted: true,
      evaluationId,
      audit: false,
    };
  }

  /** Fuse the model decision with similar past human decisions and the workspace scorer (D16). */
  private applyHistory(
    request: AutoModeEvaluationRequest,
    heads: AutoModeHeads,
    model: FusionDecision,
  ): { policy: FusionDecision; fusion?: FusionTelemetry } {
    const { summarizeNeighbours, scoreRequest } = this.deps;
    if (!summarizeNeighbours || !request.scope || !request.patternKey
      || !request.eligible || request.forcedPrompt) {
      return { policy: model };
    }
    try {
      const query: NeighbourQuery = {
        scope: request.scope,
        toolName: request.toolName,
        operation: request.operation,
        patternKey: request.patternKey,
        features: featuresFromHeads(heads),
        now: this.now(),
      };
      const summary = summarizeNeighbours(query);
      const scorer = scoreRequest?.(query);
      const extra = scorer ? { scorer } : {};
      return {
        policy: fuseWithNeighbours(model, {
          heads,
          hardRuleHit: request.hardRuleHit,
          operation: request.operation,
          summary,
          ...extra,
        }),
        fusion: { modelPolicyReason: model.reason, summary, ...extra },
      };
    } catch (error) {
      this.logStoreError("auto_mode.neighbours_failed", error);
      return { policy: model };
    }
  }

  /** Store the pre-fusion model decision so fused allows never label themselves. */
  private recordForStore(
    request: AutoModeEvaluationRequest,
    evaluationId: string,
    heads: AutoModeHeads,
    modelAction: "allow" | "prompt",
    audit: boolean,
  ): void {
    // Hard-rule prompts are the rule's job; storing them would teach denials for unrelated requests.
    if (!this.deps.recordEvaluation || !request.scope || !request.patternKey || request.hardRuleHit) return;
    try {
      this.deps.recordEvaluation({
        evaluationId,
        ts: this.now(),
        scope: request.scope,
        toolName: request.toolName,
        operation: request.operation,
        patternKey: request.patternKey,
        heads,
        hardRuleHit: request.hardRuleHit,
        modelAction,
        audit,
      });
    } catch (error) {
      this.logStoreError("auto_mode.decision_store_failed", error);
    }
  }

  private logStoreError(event: string, error: unknown): void {
    this.deps.writeDebugLog?.(event, { errorName: error instanceof Error ? error.name : "UnknownError" });
  }

  private async writeTelemetry(
    request: AutoModeEvaluationRequest,
    decision: AutoModeEvaluationDecision,
    details: {
      evaluationId: string;
      disposition: "attempted" | "skipped";
      outcome: "allowed" | "prompt" | "skipped";
      classificationLatencyMs: number;
      startupLatencyMs: number;
      totalLatencyMs: number;
      failureReason: string | null;
      modelBuildId: string | null;
      heads?: AutoModeHeads;
      audit?: boolean;
      truncated?: boolean;
      fusion?: FusionTelemetry;
      /** Model inputs for a compound Bash request, and the index of the one that decided. */
      unitCount?: number;
      decidingUnit?: number;
    },
    inputText: string,
  ): Promise<void> {
    const telemetry = {
      evaluationId: details.evaluationId,
      ...(request.toolCallId ? { toolCallId: request.toolCallId } : {}),
      flow: request.flow,
      candidate: request.candidate,
      eligible: request.eligible,
      disposition: details.disposition,
      policyThresholds: AUTO_MODE_POLICY_THRESHOLDS,
      toolName: request.toolName,
      operation: request.operation,
      pathPresent: Boolean(request.workspaceRelativePath),
      workspaceLocal: request.workspaceLocal,
      permissionState: request.permissionState,
      source: request.source,
      classificationLatencyMs: details.classificationLatencyMs,
      startupLatencyMs: details.startupLatencyMs,
      totalLatencyMs: details.totalLatencyMs,
      outcome: details.outcome,
      policyAction: decision.action,
      policyReason: decision.reason,
      failureReason: details.failureReason,
      modelBuildId: details.modelBuildId,
      ...(details.unitCount !== undefined
        ? {
            unitCount: details.unitCount,
            ...(details.decidingUnit !== undefined ? { decidingUnit: details.decidingUnit } : {}),
            opaque: request.opaque === true,
          }
        : {}),
      ...(details.fusion
        ? {
            modelPolicyReason: details.fusion.modelPolicyReason,
            fusionVersion: FUSION_VERSION,
            neighbourWorkspaceApprovals: details.fusion.summary.workspace.approvals,
            neighbourWorkspaceApprovalWeight: round2(details.fusion.summary.workspace.approvalWeight),
            neighbourWorkspaceApprovalDays: details.fusion.summary.workspace.approvalDays,
            neighbourWorkspaceLatestDeny: details.fusion.summary.workspace.latestIsDeny,
            neighbourGlobalApprovals: details.fusion.summary.global.approvals,
            neighbourGlobalApprovalWeight: round2(details.fusion.summary.global.approvalWeight),
            neighbourGlobalApprovalDays: details.fusion.summary.global.approvalDays,
            neighbourGlobalWorkspaces: details.fusion.summary.global.workspaces,
            neighbourDenials: details.fusion.summary.workspace.denials + details.fusion.summary.global.denials,
            neighbourDenialWorkspaces: details.fusion.summary.global.denialWorkspaces,
            ...(details.fusion.scorer
              ? { scorerProbability: details.fusion.scorer.probability, scorerSamples: details.fusion.scorer.samples }
              : {}),
          }
        : {}),
    };
    const calibrationRecord: AutoModeCalibrationRecord = {
      evaluationId: details.evaluationId,
      ts: new Date(this.now()).toISOString(),
      modelRev: MODEL_REVISION,
      toolName: request.toolName,
      operation: request.operation,
      textLength: inputText.length,
      textSha256: createHash("sha256").update(inputText).digest("hex"),
      truncated: details.truncated ?? request.truncated ?? false,
      heads: details.heads ?? null,
      decision: decision.action,
      reason: decision.reason,
      hardRuleHit: request.hardRuleHit,
      audit: details.audit ?? false,
      latencyMs: details.totalLatencyMs,
    };
    void Promise.resolve()
      .then(() => this.deps.writeCalibrationLog?.(calibrationRecord))
      .catch(() => {
        try {
          this.deps.writeDebugLog?.("auto_mode.calibration_write_failed", {
            evaluationId: details.evaluationId,
          });
        } catch {
          // Calibration logging cannot affect authorization.
        }
      });
    for (const writeLog of [this.deps.writeReviewLog, this.deps.writeDebugLog]) {
      try {
        writeLog?.("auto_mode.evaluation", telemetry);
      } catch {
        // Telemetry cannot affect authorization.
      }
    }
  }
}
