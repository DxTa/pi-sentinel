const SHELL_SYNTAX = /&&|\|\||[;|<>`$]|[\r\n]/;
const READ_ONLY_COMMANDS = new Set([
  "cat", "head", "tail", "grep", "rg", "ag", "wc", "sort", "uniq",
  "diff", "ls", "find", "stat", "du", "df",
]);
const SAFE_INSPECT_FIELDS = new Set(["{{.State.Status}}", "{{.State.Running}}", "{{.Config.Image}}"]);

/** True only for one simple command with no known write-capable option. */
export function isReadOnlyBashCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || SHELL_SYNTAX.test(trimmed)) return false;
  if (trimmed === "docker ps") return true;

  const [name, ...args] = trimmed.split(/\s+/);
  if (!READ_ONLY_COMMANDS.has(name ?? "")) return false;
  if (name !== "find" && ["*", "?", "["].some((char) => trimmed.includes(char))) return false;
  if (name === "find" && args.some((arg) => ["-L", "-H", "-follow"].includes(arg) || /^-(?:exec(?:dir)?|ok(?:dir)?|delete|fprint0?|fprintf|fls)$/.test(arg))) return false;
  if (name === "sort" && args.some((arg) => arg === "-o" || arg.startsWith("-o") || arg === "--output" || arg.startsWith("--output=") || arg === "--compress-program" || arg.startsWith("--compress-program="))) return false;
  if (name === "diff" && args.some((arg) => arg === "--output" || arg.startsWith("--output="))) return false;
  return true;
}

/** Curated diagnostics safe to allow without repeated approval; no arbitrary inspect output. */
export function isReadOnlyBashDiagnostic(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || SHELL_SYNTAX.test(trimmed)) return false;
  if (/^(?:orb|orbctl|docker) --help$/.test(trimmed)) return true;
  if (/^docker ps$/.test(trimmed)) return true;
  if (/^docker port [A-Za-z0-9][A-Za-z0-9_.-]*(?: \d{1,5}(?:\/(?:tcp|udp))?)?$/.test(trimmed)) return true;
  if (/^ipconfig getifaddr en\d+$/.test(trimmed)) return true;

  const inspect = trimmed.match(/^docker inspect --format (['"])(.+)\1 ([A-Za-z0-9][A-Za-z0-9_.-]*)$/);
  return Boolean(inspect && SAFE_INSPECT_FIELDS.has(inspect[2] ?? ""));
}
