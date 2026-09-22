import { randomUUID } from "node:crypto";

import { decideYoloAuto } from "./yolo-auto-policy";
import type { PermissionState } from "./types";
import type {
  YoloAutoClient,
  YoloAutoClientResult,
  YoloAutoFailureReason,
  YoloAutoPhaseSummary,
} from "./yolo-auto-client";

type EvaluationFlow = "permission" | "secret_read";
type EvaluationOperation = "read" | "list";
type EvaluationSkipReason =
  | "not_candidate"
  | "result_scanning_disabled"
  | "unsupported_tool"
  | "unstable_tool_call_id"
  | "not_workspace_local";

export interface YoloAutoEvaluationRequest {
  flow: EvaluationFlow;
  candidate: boolean;
  enabled: boolean;
  maxLevel: "l1" | "l2" | "l3";
  permissionState: PermissionState;
  source: string;
  eligible: boolean;
  forcedPrompt: boolean;
  workspaceLocal: boolean;
  operation: EvaluationOperation;
  toolName: string;
  workspaceRelativePath?: string;
  toolCallIdPresent: boolean;
  skipReason?: EvaluationSkipReason;
}

export interface YoloAutoEvaluationDecision {
  action: "allow" | "prompt";
  reason: string;
  candidate: boolean;
  attempted: boolean;
  evaluationId: string;
}

export interface YoloAutoEvaluatorDeps {
  client: Pick<YoloAutoClient, "evaluate">;
  waitForStartup?: () => Promise<void>;
  writeReviewLog?: (event: string, details: Record<string, unknown>) => void;
  now?: () => number;
}

function elapsed(now: () => number, startedAt: number): number {
  return Math.max(0, now() - startedAt);
}

function phaseSummary(result: YoloAutoClientResult): readonly YoloAutoPhaseSummary[] {
  return result.phases;
}

export class YoloAutoEvaluator {
  private readonly now: () => number;

  constructor(private readonly deps: YoloAutoEvaluatorDeps) {
    this.now = deps.now ?? Date.now;
  }

  async evaluate(request: YoloAutoEvaluationRequest): Promise<YoloAutoEvaluationDecision> {
    const startedAt = this.now();
    const evaluationId = randomUUID();
    if (!request.candidate) {
      const reason = request.skipReason ?? "not_candidate";
      const decision = {
        action: "prompt" as const,
        reason,
        candidate: false,
        attempted: false,
        evaluationId,
      };
      this.writeTelemetry(request, decision, {
        evaluationId,
        disposition: "skipped",
        outcome: "skipped",
        phases: [],
        startupLatencyMs: 0,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: reason,
        escalated: false,
      });
      return decision;
    }

    let startupLatencyMs = 0;
    if (this.deps.waitForStartup) {
      const startupStartedAt = this.now();
      try {
        await this.deps.waitForStartup();
      } catch {
        const decision = this.promptDecision(evaluationId, "startup_failed");
        this.writeTelemetry(request, decision, {
          evaluationId,
          disposition: "attempted",
          outcome: "prompt",
          phases: [],
          startupLatencyMs: elapsed(this.now, startupStartedAt),
          totalLatencyMs: elapsed(this.now, startedAt),
          failureReason: "startup_failed",
          escalated: false,
        });
        return decision;
      }
      startupLatencyMs = elapsed(this.now, startupStartedAt);
    }

    let result: YoloAutoClientResult;
    try {
      result = await this.deps.client.evaluate({
        toolName: request.toolName,
        operation: request.operation,
        ...(request.workspaceRelativePath
          ? { workspaceRelativePath: request.workspaceRelativePath }
          : {}),
        metadata: {
          input_has_path: Boolean(request.workspaceRelativePath),
          tool_call_id_present: request.toolCallIdPresent,
        },
      }, request.maxLevel);
    } catch {
      const decision = this.promptDecision(evaluationId, "transport_failure");
      this.writeTelemetry(request, decision, {
        evaluationId,
        disposition: "attempted",
        outcome: "prompt",
        phases: [],
        startupLatencyMs,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: "transport_failure",
        escalated: false,
      });
      return decision;
    }

    const resultEvaluationId = result.evaluationId;
    if (result.status === "unavailable") {
      const decision = this.promptDecision(resultEvaluationId, result.reason);
      this.writeTelemetry(request, decision, {
        evaluationId: resultEvaluationId,
        disposition: "attempted",
        outcome: "prompt",
        phases: phaseSummary(result),
        startupLatencyMs,
        totalLatencyMs: elapsed(this.now, startedAt),
        failureReason: result.reason,
        escalated: result.escalated,
      });
      return decision;
    }

    const policyDecision = decideYoloAuto({
      enabled: request.enabled,
      maxLevel: request.maxLevel,
      permissionState: request.permissionState,
      source: request.source,
      eligible: request.eligible,
      forcedPrompt: request.forcedPrompt,
      workspaceLocal: request.workspaceLocal,
      operation: request.operation,
      l1: result.l1,
      results: result.l2?.results ?? [],
      escalated: result.escalated,
    });
    const decision = {
      ...policyDecision,
      candidate: true,
      attempted: true,
      evaluationId: resultEvaluationId,
    };
    this.writeTelemetry(request, decision, {
      evaluationId: resultEvaluationId,
      disposition: "attempted",
      outcome: policyDecision.action === "allow" ? "allowed" : "prompt",
      phases: phaseSummary(result),
      startupLatencyMs,
      totalLatencyMs: elapsed(this.now, startedAt),
      failureReason: null,
      escalated: result.escalated,
    });
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
    };
  }

  private writeTelemetry(
    request: YoloAutoEvaluationRequest,
    decision: YoloAutoEvaluationDecision,
    details: {
      evaluationId: string;
      disposition: "attempted" | "skipped";
      outcome: "allowed" | "prompt" | "skipped";
      phases: readonly YoloAutoPhaseSummary[];
      startupLatencyMs: number;
      totalLatencyMs: number;
      failureReason: string | null;
      escalated: boolean;
    },
  ): void {
    try {
      this.deps.writeReviewLog?.("yolo_auto.evaluation", {
        evaluationId: details.evaluationId,
        flow: request.flow,
        disposition: details.disposition,
        toolName: request.toolName,
        operation: request.operation,
        pathPresent: Boolean(request.workspaceRelativePath),
        workspaceLocal: request.workspaceLocal,
        permissionState: request.permissionState,
        source: request.source,
        maxLevel: request.maxLevel,
        phases: details.phases,
        startupLatencyMs: details.startupLatencyMs,
        totalLatencyMs: details.totalLatencyMs,
        outcome: details.outcome,
        policyAction: decision.action,
        policyReason: decision.reason,
        failureReason: details.failureReason,
        escalated: details.escalated,
      });
    } catch {
      // Telemetry cannot affect authorization.
    }
  }
}
