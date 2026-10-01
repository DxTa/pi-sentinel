#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const THRESHOLDS = [0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.95];
const RESTRICTED_TOOL_CLASSES = new Set(["secrets", "infra", "system"]);

/** Compare each model gate with human approval labels joined by evaluationId. */
export function buildCalibrationReport(calibrationRecords, reviewEvents) {
  const labels = new Map();
  for (const event of reviewEvents) {
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
  const joined = [];
  let unlabeled = 0;
  let excluded = 0;
  for (const record of calibrationRecords) {
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
    joined: joined.length,
    unlabeled,
    excluded,
    unmatchedLabels: [...labels.keys()].filter((id) => !calibrationIds.has(id)).length,
    rows,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const agentDir = join(homedir(), ".pi", "agent");
    const calibrationPath = process.argv[2] ?? join(agentDir, "logs", "yolo-auto-calibration.jsonl");
    const reviewPath = process.argv[3] ?? join(agentDir, "extensions", "pi-sentinel", "logs", "pi-sentinel-permission-review.jsonl");
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
    );
    console.log("Joined labels: " + report.joined + "; unlabeled: " + report.unlabeled + "; excluded: " + report.excluded + "; unmatched review labels: " + report.unmatchedLabels);
    console.log("Each gate is evaluated independently; approval is positive label.");
    console.log("head\tthreshold\tn\ttp\tfp\tfn\ttn\tprecision\trecall");
    for (const row of report.rows) {
      const precision = row.precision === null ? "n/a" : row.precision.toFixed(3);
      const recall = row.recall === null ? "n/a" : row.recall.toFixed(3);
      console.log([row.head, row.threshold, row.n, row.tp, row.fp, row.fn, row.tn, precision, recall].join("\t"));
    }
    console.log("Log-only heads omitted: sensitive_document, routing, source:untrusted.");
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
