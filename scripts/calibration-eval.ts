// Run the calibration dataset through the production pre-model checks, formatter and policy.
// Usage: npx tsx scripts/calibration-eval.ts   (CALIBRATION_PROFILE=<id> PI_SENTINEL_AUTO_MODEL_DIR=<dir> for another profile)
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { buildAutoModeText } from "../src/auto-mode-client.ts";
import { MODEL_PROFILE } from "../src/auto-mode-build.ts";
import { loadModelProfile } from "../src/auto-mode-profile.ts";
import { splitBashSegments } from "../src/bash-segments.ts";
import { createClassifier } from "../src/auto-mode-model.ts";
import { decideAutoMode } from "../src/auto-mode-policy.ts";
import { isSensitivePath } from "../src/auto-mode-sensitive-paths.ts";
import { isWorkspaceLocalFileOperation } from "../src/path-utils.ts";
import { mcpArgsHaveSqlWrite } from "../src/mcp-sql-write.ts";

const modelDir = process.env.PI_SENTINEL_AUTO_MODEL_DIR
  || join(homedir(), ".pi", "agent", "runtime", "pi-sentinel", "auto-mode", "models");
const rows = JSON.parse(readFileSync(new URL("./calibration-dataset.json", import.meta.url), "utf8"));
const profile = process.env.CALIBRATION_PROFILE ? loadModelProfile(process.env.CALIBRATION_PROFILE) : MODEL_PROFILE;
const classifier = await createClassifier(modelDir, profile);
// Empty workspace so path checks run against a real directory; edit targets must exist.
const workspace = mkdtempSync(join(tmpdir(), "pi-sentinel-calibration-"));

function serialize(row, command = row.command) {
  return buildAutoModeText({ toolName: row.toolName, operation: row.operation, command,
    workspaceRelativePath: row.path, content: row.content, args: row.args }, profile.inputFormat);
}

function texts(row) {
  if (row.operation !== "exec") return [serialize(row)];
  const units = splitBashSegments(row.command) ?? [row.command];
  const whole = serialize(row);
  const parts = units.map((command) => serialize(row, command));
  return units.length === 1 && parts[0] === whole ? parts : [whole, ...parts];
}

/** File checks that run before the model in production (tool.ts): workspace containment, dotenv, system roots. */
function fileGates(row) {
  // MCP: tool.ts keeps oversized arguments and SQL writes out of auto mode before the model.
  if (row.operation === "tool") {
    const fits = buildAutoModeText({ toolName: row.toolName, operation: "tool", args: row.args }).length <= 800;
    return { workspaceLocal: fits && !mcpArgsHaveSqlWrite(row.args), hardRuleHit: false };
  }
  if (row.operation !== "write" && row.operation !== "edit") return { workspaceLocal: true, hardRuleHit: false };
  const target = resolve(workspace, row.path);
  if (row.operation === "edit" && target.startsWith(workspace + "/")) {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, "");
  }
  return {
    workspaceLocal: isWorkspaceLocalFileOperation(row.toolName, { path: row.path }, workspace),
    hardRuleHit: isSensitivePath(target, homedir()),
  };
}

const top = (heads, name) => {
  const [label, p] = Object.entries(heads[name]).reduce((a, b) => (b[1] > a[1] ? b : a));
  return label + "=" + Math.round(p * 100) + "%";
};

const stats = {};
try {
  for (const row of rows) {
    const gates = fileGates(row);
    const scored = [];
    for (const text of texts(row)) {
      const heads = await classifier.classify(text);
      scored.push({ heads, policy: decideAutoMode({
        enabled: true, permissionState: "ask", source: "tool_call", eligible: true, forcedPrompt: false,
        ...gates, sandboxed: false, operation: row.operation, toolName: row.toolName, heads,
        thresholds: profile.thresholds,
      }) });
    }
    const blocking = scored.filter((s) => s.policy.action !== "allow");
    const deciding = (blocking.length ? blocking : scored).reduce((w, n) => (n.heads.threat.benign < w.heads.threat.benign ? n : w));
    const action = blocking.length ? "prompt" : "allow";
    const h = deciding.heads;
    console.log([row.id.padEnd(5), row.group.padEnd(5), row.split.padEnd(7), row.expect.padEnd(6), action.padEnd(6),
      deciding.policy.reason.padEnd(28), "benign=" + Math.round(h.threat.benign * 100) + "%",
      "inj=" + Math.round(h.injection.injection * 100) + "%", "action=" + top(h, "tool_action"), "class=" + top(h, "tool_class")].join(" "));
    const key = row.group + " " + row.split;
    const s = (stats[key] ??= { allowOk: 0, allowN: 0, leak: 0, promptN: 0 });
    if (row.expect === "allow") { s.allowN++; if (action === "allow") s.allowOk++; }
    else { s.promptN++; if (action === "allow") s.leak++; }
  }
} finally {
  await classifier.close();
  rmSync(workspace, { recursive: true, force: true });
}
let leaks = 0;
console.log("\ngroup split   allowed(expect allow)  allowed(expect prompt)");
for (const [key, s] of Object.entries(stats).sort()) {
  leaks += s.leak;
  console.log(key.padEnd(14), (s.allowOk + "/" + s.allowN).padEnd(22), s.leak + "/" + s.promptN);
}
console.log("profile " + profile.id + ", expect-prompt allowed: " + leaks);
process.exitCode = leaks > 0 ? 1 : 0;
