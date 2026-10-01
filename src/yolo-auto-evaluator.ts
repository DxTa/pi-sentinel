import { featuresFromHeads, type EvaluationRow } from "./yolo-auto-decision-store";
import { fuseWithNeighbours, type FusionDecision } from "./yolo-auto-fusion";
import type { NeighbourQuery, NeighbourSummary } from "./yolo-auto-neighbours";
import type { ScorerResult } from "./yolo-auto-scorer";
import { createHash, randomUUID } from "node:crypto";

import { decideYoloAuto } from "./yolo-auto-policy";
import type { YoloAutoHeads } from "./yolo-auto-policy";
import { MODEL_REVISION } from "./yolo-auto-build";
import type { PermissionState } from "./types";
import { buildYoloAutoText, YoloAutoBuildMismatchError } from "./yolo-auto-client";
import type {
  YoloAutoClient,
  YoloAutoClientResult,
  YoloAutoFailureReason,
} from "./yolo-auto-client";

type EvaluationFlow = "permission" | "secret_read";
type EvaluationOperation = "read" | "list" | "write" | "edit" | "exec";
type EvaluationSkipReason =
  | "not_candidate"
  | "result_scanning_disabled"
  | "unsupported_tool"
  | "unstable_tool_call_id"
  | "not_workspace_local";

interface FusionTelemetry {
  modelPolicyReason: string;
  summary: NeighbourSummary;
  scorer?: ScorerResult;
}

export interface YoloAutoEvaluationRequest {
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

export interface YoloAutoEvaluationDecision {
  action: "allow" | "prompt";
  reason: string;
  candidate: boolean;
  attempted: boolean;
  evaluationId: string;
  audit: boolean;
}

export interface YoloAutoCalibrationRecord {
  evaluationId: string;
  ts: string;
  modelRev: string;
  toolName: string;
  operation: string;
  textLength: number;
  textSha256: string;
  truncated: boolean;
  heads: YoloAutoHeads | null;
  decision: "allow" | "prompt";
  reason: string;
  hardRuleHit: boolean;
  audit: boolean;
  latencyMs: number;
}

export interface YoloAutoEvaluatorDeps {
  client: Pick<YoloAutoClient, "evaluate">;
  waitForStartup?: () => Promise<void>;
  writeReviewLog?: (event: string, details: Record<string, unknown>) => void;
  writeDebugLog?: (event: string, details: Record<string, unknown>) => void;
  writeCalibrationLog?: (record: YoloAutoCalibrationRecord) => void | Promise<void>;
  recordEvaluation?: (row: EvaluationRow) => void;
  summarizeNeighbours?: (query: NeighbourQuery) => NeighbourSummary;
  /** Workspace scorer; undefined unless two-class history is large enough. */
  scoreRequest?: (query: NeighbourQuery) => ScorerResult | undefined;
  random?: () => number;
  now?: () => number;
}

function elapsed(now: () => number, startedAt: number): number {
  return Math.max(0, now() - startedAt);
}

export class YoloAutoEvaluator {
  private readonly now: () => number;
  private readonly random: () => number;

  constructor(private readonly deps: YoloAutoEvaluatorDeps) {
    this.now = deps.now ?? Date.now;
    this.random = deps.random ?? Math.random;
  }

  async evaluate(request: YoloAutoEvaluationRequest): Promise<YoloAutoEvaluationDecision> {
    const startedAt = this.now();
    const evaluationId = randomUUID();
    const inputText = request.text ?? buildYoloAutoText({
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

    let startupLatencyMs = 0;
    if (this.deps.waitForStartup) {
      const startupStartedAt = this.now();
      try {
        await this.deps.waitForStartup();
      } catch (error) {
        const reason = error instanceof YoloAutoBuildMismatchError ? "build_mismatch" : "startup_failed";
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

    let result: YoloAutoClientResult;
    try {
      result = await this.deps.client.evaluate(inputText);
    } catch {
      const decision = this.promptDecision(evaluationId, "transport_failure");
      await this.writeTelemetry(request, decision, {
        evaluationId,
        disposition: "attempted",
        outcome: "prompt",
        classificationLatencyMs: 0,
        startupLatencyMs,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: "transport_failure",
        modelBuildId: null,
      }, inputText);
      return decision;
    }

    const resultEvaluationId = result.evaluationId;
    if (result.status === "unavailable") {
      const decision = this.promptDecision(resultEvaluationId, result.reason);
      await this.writeTelemetry(request, decision, {
        evaluationId: resultEvaluationId,
        disposition: "attempted",
        outcome: "prompt",
        classificationLatencyMs: result.totalLatencyMs,
        startupLatencyMs,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: result.reason,
        modelBuildId: null,
      }, inputText);
      return decision;
    }

    const policyDecision = decideYoloAuto({
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
    });
    const history = this.applyHistory(request, result.heads, policyDecision);
    const finalPolicy = history.policy;
    const audit = finalPolicy.action === "allow" && this.random() < 0.05;
    const decision: YoloAutoEvaluationDecision = {
      action: audit ? "prompt" : finalPolicy.action,
      reason: audit ? "audit_sample" : finalPolicy.reason,
      candidate: true,
      attempted: true,
      evaluationId: resultEvaluationId,
      audit,
    };
    this.recordForStore(request, resultEvaluationId, result.heads, policyDecision.action);
    await this.writeTelemetry(request, decision, {
      evaluationId: resultEvaluationId,
      disposition: "attempted",
      outcome: decision.action === "allow" ? "allowed" : "prompt",
      classificationLatencyMs: result.totalLatencyMs,
      startupLatencyMs,
      totalLatencyMs: elapsed(this.now, startedAt),
      failureReason: null,
      modelBuildId: result.buildId,
      heads: result.heads,
      audit,
      ...(history.fusion ? { fusion: history.fusion } : {}),
    }, inputText);
    return decision;
  }

  private promptDecision(
    evaluationId: string,
    reason: YoloAutoFailureReason | "startup_failed" | "transport_failure" | EvaluationSkipReason,
  ): YoloAutoEvaluationDecision {
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
    request: YoloAutoEvaluationRequest,
    heads: YoloAutoHeads,
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
        policy: fuseWithNeighbours(model, { heads, hardRuleHit: request.hardRuleHit, summary, ...extra }),
        fusion: { modelPolicyReason: model.reason, summary, ...extra },
      };
    } catch (error) {
      this.logStoreError("yolo_auto.neighbours_failed", error);
      return { policy: model };
    }
  }

  /** Store the pre-fusion model decision so fused allows never label themselves. */
  private recordForStore(
    request: YoloAutoEvaluationRequest,
    evaluationId: string,
    heads: YoloAutoHeads,
    modelAction: "allow" | "prompt",
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
      });
    } catch (error) {
      this.logStoreError("yolo_auto.decision_store_failed", error);
    }
  }

  private logStoreError(event: string, error: unknown): void {
    this.deps.writeDebugLog?.(event, { errorName: error instanceof Error ? error.name : "UnknownError" });
  }

  private async writeTelemetry(
    request: YoloAutoEvaluationRequest,
    decision: YoloAutoEvaluationDecision,
    details: {
      evaluationId: string;
      disposition: "attempted" | "skipped";
      outcome: "allowed" | "prompt" | "skipped";
      classificationLatencyMs: number;
      startupLatencyMs: number;
      totalLatencyMs: number;
      failureReason: string | null;
      modelBuildId: string | null;
      heads?: YoloAutoHeads;
      audit?: boolean;
      truncated?: boolean;
      fusion?: FusionTelemetry;
    },
    inputText: string,
  ): Promise<void> {
    const telemetry = {
      evaluationId: details.evaluationId,
      ...(request.toolCallId ? { toolCallId: request.toolCallId } : {}),
      flow: request.flow,
      disposition: details.disposition,
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
      ...(details.fusion
        ? {
            modelPolicyReason: details.fusion.modelPolicyReason,
            neighbourWorkspaceApprovals: details.fusion.summary.workspace.approvals,
            neighbourGlobalApprovals: details.fusion.summary.global.approvals,
            neighbourGlobalWorkspaces: details.fusion.summary.global.workspaces,
            neighbourDenials: details.fusion.summary.workspace.denials + details.fusion.summary.global.denials,
            ...(details.fusion.scorer
              ? { scorerProbability: details.fusion.scorer.probability, scorerSamples: details.fusion.scorer.samples }
              : {}),
          }
        : {}),
    };
    const calibrationRecord: YoloAutoCalibrationRecord = {
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
          this.deps.writeDebugLog?.("yolo_auto.calibration_write_failed", {
            evaluationId: details.evaluationId,
          });
        } catch {
          // Calibration logging cannot affect authorization.
        }
      });
    for (const writeLog of [this.deps.writeReviewLog, this.deps.writeDebugLog]) {
      try {
        writeLog?.("yolo_auto.evaluation", telemetry);
      } catch {
        // Telemetry cannot affect authorization.
      }
    }
  }
}
