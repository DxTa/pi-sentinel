import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { buildAutoModeText } from "../src/auto-mode-client.ts";
import { splitBashSegments } from "../src/bash-segments.ts";
import { createClassifier } from "../src/auto-mode-model.ts";
import { decideAutoMode } from "../src/auto-mode-policy.ts";

const modelDir = process.env.PI_SENTINEL_AUTO_MODEL_DIR
  || join(homedir(), ".pi", "agent", "runtime", "pi-sentinel", "auto-mode", "models");
const rows = JSON.parse(readFileSync(new URL("./calibration-dataset.json", import.meta.url), "utf8"));
const classifier = await createClassifier(modelDir);

const FORMAT = process.env.LAYER3_FORMAT ?? "current";
const POLICY = process.env.LAYER3_POLICY ?? "strict";

// exec-relaxed: drop tool_abuse from the threat head and renormalize, so benign is judged among the other threats.
function relaxExec(heads) {
  const threat = heads.threat;
  const rest = Object.entries(threat).filter(([label]) => label !== "tool_abuse");
  const total = rest.reduce((sum, [, p]) => sum + p, 0) || 1;
  return { ...heads, threat: Object.fromEntries(rest.map(([label, p]) => [label, p / total])) };
}

function serialize(payload) {
  if (FORMAT === "current") return buildAutoModeText(payload);
  const args = payload.operation === "exec" && payload.toolName === "bash"
    ? { command: payload.command }
    : { path: payload.path ?? payload.workspaceRelativePath, content: payload.content };
  return JSON.stringify({ arguments: args, tool_name: payload.toolName }, Object.keys(args).sort().length ? sortKeys : null, 2);
}

function sortKeys(key, value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, value[k]]));
  }
  return value;
}

function texts(row) {
  if (row.operation !== "exec" || row.toolName !== "bash") {
    return [serialize(row)];
  }
  const units = splitBashSegments(row.command) ?? [row.command];
  const whole = serialize(row);
  const parts = units.map((command) => serialize({ ...row, command }));
  return units.length === 1 && parts[0] === whole ? parts : [whole, ...parts];
}

function policyFor(text, heads, row) {
  return decideAutoMode({
    enabled: true, permissionState: "ask", source: "tool_call", eligible: true,
    forcedPrompt: false, workspaceLocal: true, hardRuleHit: false, sandboxed: false,
    operation: row.operation, toolName: row.toolName, heads,
  });
}

function top(heads, name) {
  const entries = Object.entries(heads[name]);
  const [label, p] = entries.reduce((a, b) => (b[1] > a[1] ? b : a));
  return label + "=" + Math.round(p * 100) + "%";
}

let allowA = 0, allowB = 0, totalA = 0, totalB = 0;
for (const row of rows) {
  const scored = [];
  for (const text of texts(row)) {
    const heads = await classifier.classify(text);
    const judged = POLICY === "exec-relaxed" && row.operation === "exec" ? relaxExec(heads) : heads;
    scored.push({ text, heads, policy: policyFor(text, judged, row) });
  }
  const blocking = scored.filter((s) => s.policy.action !== "allow");
  const deciding = (blocking.length ? blocking : scored).reduce((w, n) =>
    n.heads.threat.benign < w.heads.threat.benign ? n : w);
  const action = blocking.length ? "prompt" : "allow";
  const worst = deciding;
  const line = [row.id.padEnd(4), row.expect.padEnd(6), action.padEnd(6),
    deciding.policy.reason.padEnd(26), "benign=" + Math.round(worst.heads.threat.benign * 100) + "%",
    "inj=" + Math.round(worst.heads.injection.injection * 100) + "%",
    "action=" + top(worst.heads, "tool_action"), "class=" + top(worst.heads, "tool_class")].join(" ");
  console.log(line);
  if (row.expect === "allow") { totalA++; if (action === "allow") allowA++; }
  if (row.expect === "prompt") { totalB++; if (action === "allow") allowB++; }
}
await classifier.close();
console.log("A allowed " + allowA + "/" + totalA + ", B allowed " + allowB + "/" + totalB);
process.exitCode = allowB > 0 ? 1 : 0;
