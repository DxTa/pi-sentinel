/**
 * Message formatting helpers for sentinel-creds prompts.
 */
import type { ScanMatch } from "./scanner";
import { mask } from "./scanner";

const MAX_CONFIRM_MATCHES = 5;

export function formatConfirmMessage(matches: ScanMatch[]): string {
  const shown = matches.slice(0, MAX_CONFIRM_MATCHES);
  const lines = shown.map((m) => `  - ${m.label} (line ${m.line}): ${m.snippet}`);
  const hidden = matches.length - shown.length;
  if (hidden > 0) lines.push(`  ... and ${hidden} more potential secret(s) not shown`);
  return [`File may contain ${matches.length} potential secret(s):`, ...lines].join("\n");
}

export function formatInputConfirmMessage(matches: ScanMatch[]): string {
  const shown = matches.slice(0, MAX_CONFIRM_MATCHES);
  const lines = shown.map((m) => `  - ${m.label} (line ${m.line}): ${m.snippet}`);
  const hidden = matches.length - shown.length;
  if (hidden > 0) lines.push(`  ... and ${hidden} more potential credential(s) not shown`);
  return [
    `Your message appears to contain ${matches.length} credential-like value(s):`,
    ...lines,
    "",
    "Credential previews are truncated.",
  ].join("\n");
}

export function formatMatchOverflow(total: number, shown: number): string[] {
  const hidden = total - shown;
  return hidden > 0 ? [`  ... and ${hidden} more potential secret(s) not shown`] : [];
}

export function formatCompactLabels(matches: ScanMatch[]): string {
  const unique = [...new Set(matches.map((m) => m.label))];
  const shown = unique.slice(0, MAX_CONFIRM_MATCHES);
  const hidden = unique.length - shown.length;
  return hidden > 0 ? `${shown.join(", ")}, and ${hidden} more type(s)` : shown.join(", ");
}

export { mask };
