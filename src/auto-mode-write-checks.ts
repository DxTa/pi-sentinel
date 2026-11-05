// shortcut: keyword checks on write/edit content, not a parser. They add prompts only; reworded attacks
// and stores not listed here (for example container registry configs) still reach the model.
// Extend the patterns from calibration misses (npm run calibrate).
import { hasAgentDirective } from "./agent-directive.ts";
import { CREDENTIAL_DIRS } from "./yolo-forbidden-paths.ts";

// Secret-named environment variables (uppercase by convention): GITHUB_TOKEN, DB_PASSWORD, API_KEY, ...
const SECRET_NAME = String.raw`[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*`;
const SECRET_VAR = new RegExp(String.raw`\$\{?${SECRET_NAME}\b|process\.env\.${SECRET_NAME}\b|process\.env\[['"]${SECRET_NAME}['"]\]|os\.environ(?:\.get\(|\[)\s*['"]${SECRET_NAME}['"]|getenv\(\s*['"]${SECRET_NAME}['"]`);
// The whole environment holds every secret.
const ENV_DUMP = /JSON\.stringify\(\s*process\.env\s*\)|\bdict\(\s*os\.environ\s*\)|\bprintenv\b|\benv\s*\|/;
// Home credential stores: the folders yolo never writes, plus cloud CLI and netrc files.
const CREDENTIAL_STORE = new RegExp(String.raw`(?:^|[/'"\s])\.(?:${CREDENTIAL_DIRS.map((d) => d.slice(1)).join("|")})/|\.config/gcloud\b|\.netrc\b`);
// Files coding agents read as instructions: a write there steers every later session.
const AGENT_INSTRUCTION_FILE = /(?:^|\/)(?:AGENTS|CLAUDE|GEMINI)\.md$|(?:^|\/)\.(?:cursorrules|windsurfrules|clinerules)$|(?:^|\/)\.github\/copilot-instructions\.md$|(?:^|\/)\.cursor\/rules\/|(?:^|\/)\.pi\//i;

export function hasSecretReference(text: string | undefined): boolean {
  return Boolean(text) && (SECRET_VAR.test(text!) || ENV_DUMP.test(text!) || CREDENTIAL_STORE.test(text!));
}

export function isAgentInstructionPath(path: string | undefined): boolean {
  return Boolean(path) && AGENT_INSTRUCTION_FILE.test(path!.replaceAll("\\", "/"));
}

/** Write/edit checks that run before the model: such writes always prompt in auto mode. */
export function writeNeedsPrompt(path: string | undefined, content: string | undefined): boolean {
  return isAgentInstructionPath(path) || hasAgentDirective(content) || hasSecretReference(content);
}
