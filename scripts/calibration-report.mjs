#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const THRESHOLDS = [0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.95];
const RESTRICTED_TOOL_CLASSES = new Set(["secrets", "infra", "system"]);

function buildCoverageRows(records, labels, telemetryById) {
  const groups = new Map();
  for (const record of records) {
    const id = typeof record?.evaluationId === "string" ? record.evaluationId : undefined;
    const telemetry = id ? telemetryById.get(id) : undefined;
    const flow = telemetry?.flow ?? "not-recorded";
    const toolName = record?.toolName ?? telemetry?.toolName ?? "unknown";
    const operation = record?.operation ?? telemetry?.operation ?? "unknown";
    const policyThresholds = telemetry?.policyThresholds ?? null;
    const thresholdSet = policyThresholds ? JSON.stringify(policyThresholds) : "not-recorded";
    const modelBuildId = telemetry?.modelBuildId ?? record?.modelRev ?? "not-recorded";
    // Pattern keys are low-entropy and may reveal commands or paths in exported telemetry.
    const key = JSON.stringify([flow, toolName, operation, thresholdSet, modelBuildId]);
    let row = groups.get(key);
    if (!row) {
      row = {
        flow, toolName, operation, policyThresholds, modelBuildId,
        evaluations: 0, candidates: 0, candidateMetadataMissing: 0,
        eligible: 0, eligibilityMetadataMissing: 0,
        attempted: 0, skipped: 0, dispositionMetadataMissing: 0,
        scored: 0, allowed: 0, prompted: 0,
        labelled: 0, unlabelled: 0, humanApproved: 0, humanDenied: 0,
        hardRuleHits: 0, failures: 0, missingHeads: 0, auditSamples: 0, reasons: {},
      };
      groups.set(key, row);
    }

    row.evaluations++;
    if (typeof telemetry?.candidate === "boolean") row.candidates += Number(telemetry.candidate);
    else row.candidateMetadataMissing++;
    if (typeof telemetry?.eligible === "boolean") row.eligible += Number(telemetry.eligible);
    else row.eligibilityMetadataMissing++;
    if (telemetry?.disposition === "attempted") row.attempted++;
    else if (telemetry?.disposition === "skipped") row.skipped++;
    else row.dispositionMetadataMissing++;
    if (record?.heads && typeof record.heads === "object") row.scored++;
    if (record?.decision === "allow") row.allowed++;
    if (record?.decision === "prompt") row.prompted++;
    if (id && labels.has(id)) {
      row.labelled++;
      if (labels.get(id)) row.humanApproved++;
      else row.humanDenied++;
    } else {
      row.unlabelled++;
    }
    if (record?.hardRuleHit === true) row.hardRuleHits++;
    if (telemetry?.disposition === "attempted" && telemetry.failureReason) row.failures++;
    if (!record?.heads || typeof record.heads !== "object") row.missingHeads++;
    if (record?.audit === true) row.auditSamples++;
    const reason = record?.reason ?? telemetry?.policyReason ?? "not-recorded";
    row.reasons[reason] = (row.reasons[reason] ?? 0) + 1;
  }

  return [...groups.values()].sort((a, b) => JSON.stringify([
    a.flow, a.toolName, a.operation, a.modelBuildId, a.policyThresholds,
  ]).localeCompare(JSON.stringify([
    b.flow, b.toolName, b.operation, b.modelBuildId, b.policyThresholds,
  ])));
}

/** Compare each model gate with human approval labels joined by evaluationId. */
export function buildCalibrationReport(calibrationRecords, reviewEvents, { since, until } = {}) {
  const labels = new Map();
  const telemetryById = new Map();
  for (const event of reviewEvents) {
    if (event?.event === "yolo_auto.evaluation" && typeof event.evaluationId === "string") {
      telemetryById.set(event.evaluationId, event);
    }
    const approved = event?.event === "permission_request.approved";
    if ((!approved && event?.event !== "permission_request.denied")
      || typeof event.evaluationId !== "string") continue;
    const label = approved;
    const previous = labels.get(event.evaluationId);
    if (previous !== undefined && previous !== label) {
      throw new Error("Conflicting human labels for evaluation " + event.evaluationId);
    }
    labels.set(event.evaluationId, label);
  }

  const calibrationIds = new Set(calibrationRecords.map((record) => record?.evaluationId).filter((id) => typeof id === "string"));
  const hasWindow = since !== undefined || until !== undefined;
  let invalidTimestamps = 0;
  const selectedRecords = hasWindow ? calibrationRecords.filter((record) => {
    const timestamp = Date.parse(record?.ts ?? "");
    if (!Number.isFinite(timestamp)) {
      invalidTimestamps++;
      return false;
    }
    return (since === undefined || timestamp >= since)
      && (until === undefined || timestamp < until);
  }) : calibrationRecords;
  const joined = [];
  let unlabeled = 0;
  let excluded = 0;
  for (const record of selectedRecords) {
    if (typeof record?.evaluationId !== "string" || !labels.has(record.evaluationId)) {
      unlabeled++;
      continue;
    }
    if (record.hardRuleHit || !record.heads || typeof record.heads !== "object") {
      excluded++;
      continue;
    }
    joined.push({ record, approved: labels.get(record.evaluationId) });
  }

  const rows = [];
  const argmax = (distribution) => {
    if (!distribution || typeof distribution !== "object") return undefined;
    let label;
    let highest = -Infinity;
    let tied = false;
    for (const [candidate, score] of Object.entries(distribution)) {
      if (typeof score !== "number" || !Number.isFinite(score)) return undefined;
      if (score > highest) {
        label = candidate;
        highest = score;
        tied = false;
      } else if (score === highest) {
        tied = true;
      }
    }
    return tied ? undefined : label;
  };
  const measure = (head, threshold, predictsAllow) => {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    let tn = 0;
    for (const { record, approved } of joined) {
      const predicted = predictsAllow(record);
      if (predicted && approved) tp++;
      else if (predicted) fp++;
      else if (approved) fn++;
      else tn++;
    }
    rows.push({
      head,
      threshold,
      n: joined.length,
      tp,
      fp,
      fn,
      tn,
      precision: tp + fp === 0 ? null : tp / (tp + fp),
      recall: tp + fn === 0 ? null : tp / (tp + fn),
    });
  };
  const score = (record, head, label) => record.heads[head]?.[label];

  for (const threshold of THRESHOLDS) {
    const formatted = threshold.toFixed(2);
    measure("threat.benign", ">=" + formatted, (record) =>
      argmax(record.heads.threat) === "benign"
      && typeof score(record, "threat", "benign") === "number"
      && score(record, "threat", "benign") >= threshold);
    measure("injection.injection", "<" + formatted, (record) =>
      typeof score(record, "injection", "injection") === "number"
      && score(record, "injection", "injection") < threshold);
    for (const tag of ["source:sensitive", "sink:external"]) {
      measure("tool_tags." + tag, "<" + formatted, (record) =>
        typeof score(record, "tool_tags", tag) === "number"
        && score(record, "tool_tags", tag) < threshold);
    }
  }

  measure("tool_action", "argmax", (record) => {
    const expected = record.operation === "edit" ? "write" : record.operation;
    return argmax(record.heads.tool_action) === expected;
  });
  measure("tool_class", "argmax", (record) => {
    const predicted = argmax(record.heads.tool_class);
    return predicted !== undefined && !RESTRICTED_TOOL_CLASSES.has(predicted);
  });

  return {
    totalEvaluations: selectedRecords.length,
    invalidTimestamps,
    joined: joined.length,
    unlabeled,
    excluded,
    unmatchedLabels: [...labels.keys()].filter((id) => !calibrationIds.has(id)).length,
    coverage: buildCoverageRows(selectedRecords, labels, telemetryById),
    rows,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { values, positionals } = parseArgs({
      args: process.argv.slice(2),
      options: { since: { type: "string" }, until: { type: "string" } },
      allowPositionals: true,
    });
    if (positionals.length > 2) {
      throw new Error("Usage: node scripts/calibration-report.mjs [calibration.jsonl] [review.jsonl] [--since ISO] [--until ISO]");
    }
    const parseBound = (value, option) => {
      if (value === undefined) return undefined;
      if (!/T.*(?:Z|[+-]\d{2}:?\d{2})$/i.test(value)) {
        throw new Error(option + " must be an ISO-8601 timestamp with timezone");
      }
      const timestamp = Date.parse(value);
      if (!Number.isFinite(timestamp)) throw new Error(option + " is not a valid timestamp");
      return timestamp;
    };
    const since = parseBound(values.since, "--since");
    const until = parseBound(values.until, "--until");
    if (since !== undefined && until !== undefined && since >= until) {
      throw new Error("--since must be earlier than --until");
    }

    const agentDir = join(homedir(), ".pi", "agent");
    const calibrationPath = positionals[0] ?? join(agentDir, "logs", "yolo-auto-calibration.jsonl");
    const reviewPath = positionals[1] ?? join(agentDir, "extensions", "pi-sentinel", "logs", "pi-sentinel-permission-review.jsonl");
    const readJsonl = (file) => readFileSync(file, "utf8").split(/\r?\n/).flatMap((line, index) => {
      if (!line.trim()) return [];
      try {
        return [JSON.parse(line)];
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(file + ":" + (index + 1) + ": " + message);
      }
    });
    const calibrationFiles = [calibrationPath + ".1", calibrationPath].filter(existsSync);
    if (calibrationFiles.length === 0) throw new Error("Calibration log not found: " + calibrationPath);
    const report = buildCalibrationReport(
      calibrationFiles.flatMap(readJsonl),
      readJsonl(reviewPath),
      { since, until },
    );
    const window = since === undefined && until === undefined
      ? "all available records"
      : (since === undefined ? "-infinity" : new Date(since).toISOString())
        + " inclusive to "
        + (until === undefined ? "+infinity" : new Date(until).toISOString())
        + " exclusive";
    console.log("Evaluation window: " + window);
    console.log("Evaluations: " + report.totalEvaluations + "; invalid timestamps excluded: " + report.invalidTimestamps);
    console.log("Joined labels: " + report.joined + "; unlabeled: " + report.unlabeled + "; excluded: " + report.excluded + "; unmatched review labels: " + report.unmatchedLabels);
    console.log("Human approval is the positive label; these are independent gate metrics, not a safety-ground-truth estimate.");
    const thresholdSets = new Set(report.coverage.map((row) => JSON.stringify(row.policyThresholds)));
    if (report.coverage.length > 0 && report.coverage.some((row) => row.policyThresholds === null)) {
      console.log("WARNING: some evaluations lack a runtime threshold snapshot; gate metrics pool known and unknown policies.");
    } else if (report.coverage.length > 0 && thresholdSets.size !== 1) {
      console.log("WARNING: gate metrics pool multiple runtime threshold snapshots; use the coverage rows to separate them.");
    }
    console.log("head\tthreshold\tn\ttp\tfp\tfn\ttn\tprecision\trecall");
    for (const row of report.rows) {
      const precision = row.precision === null ? "n/a" : row.precision.toFixed(3);
      const recall = row.recall === null ? "n/a" : row.recall.toFixed(3);
      console.log([row.head, row.threshold, row.n, row.tp, row.fp, row.fn, row.tn, precision, recall].join("\t"));
    }
    console.log("\nCoverage by flow/tool/operation/model/policy-thresholds:");
    console.log("flow\ttool\toperation\tmodel_build\tpolicy_thresholds\tevaluations\tcandidates\tcandidate_metadata_missing\teligible\teligibility_metadata_missing\tattempted\tskipped\tdisposition_metadata_missing\tscored\tallowed\tprompted\tlabelled\tunlabelled\thuman_approved\thuman_denied\thard_rule_hits\tfailures\tmissing_heads\taudit_samples\treasons");
    for (const row of report.coverage) {
      const reasons = Object.entries(row.reasons).sort(([a], [b]) => a.localeCompare(b)).map(([reason, count]) => reason + ":" + count).join(",");
      console.log([
        row.flow, row.toolName, row.operation, row.modelBuildId,
        row.policyThresholds ? JSON.stringify(row.policyThresholds) : "not-recorded",
        row.evaluations, row.candidates, row.candidateMetadataMissing, row.eligible,
        row.eligibilityMetadataMissing, row.attempted, row.skipped,
        row.dispositionMetadataMissing, row.scored,
        row.allowed, row.prompted, row.labelled, row.unlabelled, row.humanApproved,
        row.humanDenied, row.hardRuleHits, row.failures, row.missingHeads,
        row.auditSamples, reasons,
      ].join("\t"));
    }
    console.log("Log-only heads omitted from gate sweeps: sensitive_document, routing, source:untrusted.");
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
