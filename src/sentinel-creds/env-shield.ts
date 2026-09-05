/**
 * Env-shield: detect bash commands that dump environment variables.
 */

const SHELL_COMMAND_PREFIX = String.raw`(?:^|[;&|()\n]|\b(?:then|do|else|if|while|until|for|command|builtin)\s+)`;
const ENV_DUMP_ARGUMENTS = String.raw`(?:(?:\s+-u\s+[A-Z_][A-Z0-9_]*)|(?:\s+(?:-[A-Za-z0-9]+|--[A-Za-z0-9-]*|[A-Z_][A-Z0-9_]*=(?:'[^']*'|"[^"]*"|[^\s;&|()]+))))*`;
const SHELL_REDIRECTIONS = String.raw`(?:\s*[0-9]*[<>]{1,2}\s*(?:'[^']*'|"[^"]*"|[^\s;&|()]+))*`;
const ENV_DUMP_COMMANDS: RegExp[] = [
  new RegExp(`${SHELL_COMMAND_PREFIX}\\s*(?:[^\\s;&|()]+/)*env${ENV_DUMP_ARGUMENTS}${SHELL_REDIRECTIONS}\\s*(?:[|;&)}>]|$)`),
  new RegExp(`${SHELL_COMMAND_PREFIX}\\s*(?:[^\\s;&|()]+/)*printenv(?:\\s|$|[|;&)}>])`),
  new RegExp(`${SHELL_COMMAND_PREFIX}\\s*declare\\s+-x\\s*${SHELL_REDIRECTIONS}\\s*(?:[|;&)}>]|$)`),
  new RegExp(`${SHELL_COMMAND_PREFIX}\\s*declare\\s+-xp(?:\\s|$|[|;&)}>])`),
  new RegExp(`${SHELL_COMMAND_PREFIX}\\s*declare\\s+-x\\s+-p(?:\\s|$|[|;&)}>])`),
  new RegExp(`${SHELL_COMMAND_PREFIX}\\s*set\\s*${SHELL_REDIRECTIONS}\\s*(?:[|;&)}>]|$)`),
];
const EXPORT_LIST_COMMAND = new RegExp(
  `${SHELL_COMMAND_PREFIX}\\s*export(?:\\s+(?:-p|--)(?:\\s|[|;&)}>]|$)|${SHELL_REDIRECTIONS}\\s*(?:[|;&)}>]|$))`,
  "i",
);

// Secret-named env vars (excludes bare AUTH to avoid matching AUTHORIZATION etc.)
const SECRET_VAR_PATTERN = /\$\{?([A-Z_][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API|PRIVATE|ACCESS))\b/;
const AUTH_SECRET_VAR_PATTERN = /\$\{?([A-Z_][A-Z0-9_]*(?:AUTH_TOKEN|AUTH_KEY|AUTH_SECRET|AUTH_PASS|AUTH_CREDENTIAL))\b/i;

/**
 * Check if `env | grep ...` pipeline only filters to safe prefixes.
 */
function envGrepOnlySafePrefixes(command: string, safePrefixes: string[]): boolean {
  if (safePrefixes.length === 0) return false;
  const normalizedPrefixes = safePrefixes.map((p) => p.toUpperCase());
  const trimmed = command.trim();
  const envPipeline = /^(?:env|printenv)\s*\|\s*(?:grep|egrep|fgrep)\s+(?:-[iEl]+\s+)*['"]?\^([A-Z_][A-Z0-9_]*_?)['"]?\s*$/i.exec(trimmed);
  if (!envPipeline) return false;
  const target = envPipeline[1].toUpperCase();
  return normalizedPrefixes.some((prefix) => target.startsWith(prefix.toUpperCase()));
}

/**
 * Check if a bash command would dump env variables containing secrets.
 * Returns a reason string or null if safe.
 */
export function checkEnvExposure(command: string, safeEnvPrefixes: string[]): string | null {
  for (const pat of ENV_DUMP_COMMANDS) {
    if (pat.test(command)) {
      if (envGrepOnlySafePrefixes(command, safeEnvPrefixes)) {
        return null;
      }
      return "Command dumps environment variables which may contain secrets.";
    }
  }

  // Bare `export` and `export -p` list exported vars; assignments do not.
  if (EXPORT_LIST_COMMAND.test(command)) {
    return "Command lists exported environment variables which may contain secrets.";
  }

  // `echo $SECRET_VAR`, `printf "$SECRET_VAR"`, etc.
  const authMatch = AUTH_SECRET_VAR_PATTERN.test(command);
  const secretMatch = SECRET_VAR_PATTERN.test(command);
  if (authMatch || secretMatch) {
    const match = command.match(authMatch ? AUTH_SECRET_VAR_PATTERN : SECRET_VAR_PATTERN);
    const varName = match?.[1] ?? "unknown";
    return `Command expands secret environment variable: $${varName}`;
  }

  // `node -e 'console.log(process.env)'`
  if (/\b(?:node|python3?|ruby|perl)\b.*(?:process\s*(?:\.\s*env|\[\s*["']env["']\s*\])|os\s*\.\s*environ|(?<![\w."'])ENV\b)/i.test(command)) {
    return "Command accesses programmatic environment object which may contain secrets.";
  }

  return null;
}
