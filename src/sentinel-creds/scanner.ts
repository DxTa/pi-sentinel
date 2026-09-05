/**
 * Secret pattern matching, entropy calculation, and redaction.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const GITLEAKS_TIMEOUT_MS = 5_000;
const GITLEAKS_MAX_BUFFER = 1_048_576;
let gitleaksMissing = false;

export interface ScanMatch {
  label: string;
  line: number;
  snippet: string;
  value?: string;
}

export interface ScanResult {
  hasSecrets: boolean;
  matches: ScanMatch[];
}

interface SecretPattern {
  label: string;
  regex: RegExp;
}

interface GitleaksFinding {
  RuleID?: unknown;
  Description?: unknown;
  StartLine?: unknown;
  Match?: unknown;
  Secret?: unknown;
  Line?: unknown;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
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
  { label: "Database URL with password", regex: /(?:mysql|postgres|mongodb|redis):\/\/[^:\s]+:[^@\s]+@/i },
  { label: ".npmrc auth token", regex: /_authToken\s*=\s*\S{8,}/ },
  { label: ".netrc password", regex: /password\s+\S{8,}/ },
];

const ENTROPY_THRESHOLD = 4.0;
const ENTROPY_MIN_LENGTH = 16;
const ENV_ASSIGNMENT = /^([A-Z_][A-Z0-9_]*)\s*=\s*['"]?([^'"#\s]+)['"]?/gm;

export const MAX_SCAN_BYTES = 1_048_576; // 1 MB

const FAKE_INDICATORS = [
  /\bexample\b/i,
  /\bdummy\b/i,
  /\bplaceholder\b/i,
  /\bchangeme\b/i,
  /\btest\b/i,
  /\bfake\b/i,
  /\bsample\b/i,
  /\blocalhost\b/i,
  /["'][A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)["']/,
  /["'](?:PROXY|LOCAL|YOUR|MY)_[A-Z0-9_]+["']/,
  /\bxxx+\b/,
  /\b12345678\b/,
  /\bpassword\b/i,
  /\byour[_-]?(?:api|secret|token|key)\b/i,
  /\bdefault\b/i,
  /\btemplate\b/i,
  /\bnone\b/i,
  /\bnull\b/i,
  /\bFIXME\b/i,
  /\bTODO\b/i,
  /\bREPLACE_?ME\b/i,
  /\bINSERT_?HERE\b/i,
  /\bN\/A\b/i,
  /\bna\b/i,
  /\boverride\b/i,
  /\bignored?\b/i,
  /\b0{4,}\b/,
  /\b9{4,}\b/,
  /\b[aA]{4,}\b/,
  /\b[xX]{4,}\b/,
];

function shannonEntropy(value: string): number {
  const freq = new Map<string, number>();
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isLikelyFake(snippet: string): boolean {
  return FAKE_INDICATORS.some((pattern) => pattern.test(snippet));
}

export function mask(value: string): string {
  if (value.length <= 10) return `${value.slice(0, 3)}****`;
  return `${value.slice(0, 4)}****${value.slice(-4)}`;
}

function mergeMatches(...groups: ScanMatch[][]): ScanMatch[] {
  const seen = new Set<string>();
  const merged: ScanMatch[] = [];

  for (const group of groups) {
    for (const match of group) {
      const key = JSON.stringify([match.label, match.line, match.snippet, match.value ?? ""]);
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(match);
    }
  }

  return merged;
}

function scanPatternMatches(content: string): ScanMatch[] {
  const matches: ScanMatch[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const { label, regex } of SECRET_PATTERNS) {
      const match = regex.exec(line);
      if (!match || isLikelyFake(match[0])) continue;
      matches.push({ label, line: lineNum, snippet: mask(match[0]), value: match[0] });
    }
  }

  return matches;
}

function scanEntropyMatches(content: string): ScanMatch[] {
  const matches: ScanMatch[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    let envMatch: RegExpExecArray | null;
    ENV_ASSIGNMENT.lastIndex = 0;
    while ((envMatch = ENV_ASSIGNMENT.exec(line)) !== null) {
      const key = envMatch[1];
      const value = envMatch[2];
      if (
        value.length >= ENTROPY_MIN_LENGTH &&
        shannonEntropy(value) >= ENTROPY_THRESHOLD &&
        !isLikelyFake(value) &&
        !isLikelyFake(line)
      ) {
        matches.push({
          label: "High-Entropy Value",
          line: lineNum,
          snippet: `${key}=${mask(value)}`,
          value,
        });
      }
    }
  }

  return matches;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function asLineNumber(value: unknown): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : 1;
}

function buildMaskedSnippet(matchText: string | undefined, secret: string | undefined, label: string): string {
  if (secret && matchText?.includes(secret)) {
    return matchText.split(secret).join(mask(secret));
  }
  if (secret) return mask(secret);
  if (matchText) return mask(matchText);
  return `[REDACTED: ${label}]`;
}

function parseGitleaksReport(content: string): ScanResult | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch {
    return null;
  }

  if (!Array.isArray(parsed)) return null;

  const matches = parsed.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const finding = entry as GitleaksFinding;
    const label = asString(finding.RuleID) ?? asString(finding.Description) ?? "Gitleaks Finding";
    const value = asString(finding.Secret) ?? asString(finding.Match);
    const matchText = asString(finding.Match) ?? asString(finding.Line) ?? value;

    return [{
      label,
      line: asLineNumber(finding.StartLine),
      snippet: buildMaskedSnippet(matchText, value, label),
      value,
    } satisfies ScanMatch];
  });

  return { hasSecrets: matches.length > 0, matches };
}

function getGitleaksBinary(): string {
  return process.env.PI_GITLEAKS_BIN?.trim() || "gitleaks";
}

function hasCustomGitleaksBinary(): boolean {
  return Boolean(process.env.PI_GITLEAKS_BIN?.trim());
}

async function runGitleaksDirScan(targetPath: string): Promise<ScanResult | null> {
  if (gitleaksMissing && !hasCustomGitleaksBinary()) return null;

  let tempDir: string | undefined;
  try {
    tempDir = await mkdtemp(join(tmpdir(), "pi-gitleaks-"));
    const reportPath = join(tempDir, "report.json");
    await execFileAsync(
      getGitleaksBinary(),
      [
        "dir",
        targetPath,
        "--report-format",
        "json",
        "--report-path",
        reportPath,
        "--exit-code",
        "0",
        "--no-banner",
        "--no-color",
        "--log-level",
        "error",
      ],
      { timeout: GITLEAKS_TIMEOUT_MS, maxBuffer: GITLEAKS_MAX_BUFFER },
    );
    const report = await readFile(reportPath, "utf8");
    return parseGitleaksReport(report);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !hasCustomGitleaksBinary()) {
      gitleaksMissing = true;
    }
    return null;
  } finally {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

async function readUtf8IfAvailable(targetPath: string, content?: string): Promise<string | null> {
  if (typeof content === "string") return content;
  try {
    return await readFile(targetPath, "utf8");
  } catch {
    return null;
  }
}

export function scanForSecrets(content: string): ScanResult {
  const matches = mergeMatches(scanPatternMatches(content), scanEntropyMatches(content));
  return { hasSecrets: matches.length > 0, matches };
}

export async function scanPathForSecrets(targetPath: string, content?: string): Promise<ScanResult | null> {
  const utf8Content = await readUtf8IfAvailable(targetPath, content);
  const patternMatches = utf8Content ? scanPatternMatches(utf8Content) : [];
  const gitleaksResult = await runGitleaksDirScan(targetPath);

  if (gitleaksResult) {
    const matches = mergeMatches(patternMatches, gitleaksResult.matches);
    return { hasSecrets: matches.length > 0, matches };
  }

  if (utf8Content === null) return null;
  return scanForSecrets(utf8Content);
}

export async function scanContentForSecrets(content: string): Promise<ScanResult> {
  const patternMatches = scanPatternMatches(content);

  let tempDir: string | undefined;
  try {
    tempDir = await mkdtemp(join(tmpdir(), "pi-gitleaks-content-"));
    const tempFilePath = join(tempDir, "snippet.txt");
    await writeFile(tempFilePath, content, "utf8");
    const gitleaksResult = await runGitleaksDirScan(tempFilePath);
    if (gitleaksResult !== null) {
      const matches = mergeMatches(patternMatches, gitleaksResult.matches);
      return { hasSecrets: matches.length > 0, matches };
    }
  } catch {
    // Fall back to heuristic scanner below.
  } finally {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  return scanForSecrets(content);
}

export function isBinaryContent(content: string): boolean {
  return content.slice(0, 512).includes("\0");
}

function toGlobalRegex(regex: RegExp): RegExp {
  return new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : `${regex.flags}g`);
}

/**
 * Redact secret values from content, replacing with [REDACTED: <label>].
 */
export function redactSecrets(content: string, matches: ScanMatch[] = []): string {
  let redacted = content;
  for (const { regex, label } of SECRET_PATTERNS) {
    redacted = redacted.replace(toGlobalRegex(regex), `[REDACTED: ${label}]`);
  }
  for (const match of matches) {
    if (match.value && match.value.length >= ENTROPY_MIN_LENGTH) {
      redacted = redacted.split(match.value).join(`[REDACTED: ${match.label}]`);
    }
  }
  return redacted;
}
