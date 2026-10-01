/**
 * Decision-store reporting and denial export (D16).
 * The export carries denials only, with salted pattern-key hashes and an HMAC
 * signature, so a future central store can ingest it without raw commands.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

import type { DecisionRecord } from "./yolo-auto-decision-store";

export interface DecisionReportRow {
  toolName: string;
  operation: string;
  labelled: number;
  unlabelled: number;
  modelAllowHumanDeny: number;
  modelPromptHumanApprove: number;
  /** Denied share of labelled rows the model allowed (0 when none). */
  falseAllowRate: number;
  approvalRate: number;
}

export function buildDecisionReport(records: readonly DecisionRecord[]): DecisionReportRow[] {
  const groups = new Map<string, DecisionRecord[]>();
  for (const r of records) {
    const key = `${r.toolName}\u0000${r.operation}`;
    groups.set(key, [...(groups.get(key) ?? []), r]);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, rows]) => {
      const labelled = rows.filter((r) => r.humanAction !== null);
      const approvals = labelled.filter((r) => r.humanAction !== "deny").length;
      const modelAllowed = labelled.filter((r) => r.modelAction === "allow");
      const modelAllowHumanDeny = modelAllowed.filter((r) => r.humanAction === "deny").length;
      return {
        toolName: rows[0]!.toolName,
        operation: rows[0]!.operation,
        labelled: labelled.length,
        unlabelled: rows.length - labelled.length,
        modelAllowHumanDeny,
        modelPromptHumanApprove: labelled.filter((r) => r.modelAction === "prompt" && r.humanAction !== "deny").length,
        falseAllowRate: modelAllowed.length === 0 ? 0 : modelAllowHumanDeny / modelAllowed.length,
        approvalRate: labelled.length === 0 ? 0 : approvals / labelled.length,
      };
    });
}

export interface DenialExportEntry {
  toolName: string;
  operation: string;
  patternKeyHash: string;
  features: number[];
  decidedAt: number;
}

export interface DenialExport {
  exportedAt: number;
  entries: DenialExportEntry[];
  signature: string;
}

const sign = (key: string, body: Omit<DenialExport, "signature">): string =>
  createHmac("sha256", key).update(JSON.stringify(body)).digest("hex");

export function exportDenials(
  records: readonly DecisionRecord[],
  options: { salt: string; key: string; now: number },
): DenialExport {
  const body = {
    exportedAt: options.now,
    entries: records
      .filter((r) => r.humanAction === "deny")
      .map((r) => ({
        toolName: r.toolName,
        operation: r.operation,
        patternKeyHash: createHmac("sha256", options.salt).update(r.patternKey).digest("hex").slice(0, 32),
        features: r.features,
        decidedAt: r.humanTs ?? r.ts,
      })),
  };
  return { ...body, signature: sign(options.key, body) };
}

export function verifyDenialExport(exported: DenialExport, key: string): boolean {
  const expected = Buffer.from(sign(key, { exportedAt: exported.exportedAt, entries: exported.entries }), "hex");
  const actual = Buffer.from(exported.signature, "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
