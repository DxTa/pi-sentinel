/** Secret-pattern redaction for sensitive local logs. */
interface SecretPattern {
  label: string;
  regex: RegExp;
}

const SECRET_PATTERNS: readonly SecretPattern[] = [
  { label: "AWS Access Key", regex: /AKIA[A-Z0-9]{16}/ },
  { label: "AWS Secret Key", regex: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*\S{20,}/i },
  { label: "GitHub Token", regex: /gh[ps]_[a-zA-Z0-9]{36,}/ },
  { label: "GitHub OAuth Token", regex: /gho_[a-zA-Z0-9]{36,}/ },
  { label: "GitLab Token", regex: /glpat-[a-zA-Z0-9\-]{20,}/ },
  { label: "Anthropic Key", regex: /sk-ant-[a-zA-Z0-9_-]{20,}/ },
  { label: "OpenAI Key", regex: /sk-[a-zA-Z0-9]{40,}/ },
  { label: "Google API Key", regex: /AIza[a-zA-Z0-9_-]{35}/ },
  { label: "Google OAuth Secret", regex: /GOCSPX-[a-zA-Z0-9_-]{28,}/ },
  { label: "Slack Token", regex: /xox[bpsa]-[a-zA-Z0-9-]{10,}/ },
  { label: "Stripe Key", regex: /[sr]k_(?:live|test)_[a-zA-Z0-9]{20,}/ },
  { label: "npm Token", regex: /npm_[a-zA-Z0-9]{36,}/ },
  { label: "PyPI Token", regex: /pypi-[a-zA-Z0-9_-]{20,}/ },
  { label: "HuggingFace Token", regex: /hf_[a-zA-Z0-9]{34,}/ },
  { label: "PEM Private Key", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/ },
  { label: "Generic Secret", regex: /\b(?:secret|password|token|api_key|apikey|api-key)\b\s*[=:]\s*['"][^'"]{12,}['"]/i },
  { label: "Generic Secret (unquoted)", regex: /\b(?:secret|password|token|api_key|apikey|api-key)\b\s*[=:]\s*[A-Za-z0-9_+=/-]{16,}\b/i },
  { label: "Env Assignment (quoted)", regex: /^[A-Z_][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE)\s*=\s*['"][^'"]{12,}['"]/m },
  { label: "Database URL with password", regex: /(?:mysql|postgres|mongodb|redis):\/\/[^:\s]+:[^@\s]+@(?=((?:\[[^\]\s]*\]|[^\s/?#:]*)(?::\d+)?))/i },
  { label: ".npmrc auth token", regex: /_authToken\s*=\s*\S{8,}/ },
  { label: ".netrc password", regex: /password\s+\S{8,}/ },
];

function toGlobalRegex(regex: RegExp): RegExp {
  return new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : `${regex.flags}g`);
}

export function redactSecrets(content: string): string {
  let redacted = content;
  for (const { regex, label } of SECRET_PATTERNS) {
    redacted = redacted.replace(toGlobalRegex(regex), `[REDACTED: ${label}]`);
  }
  return redacted;
}
