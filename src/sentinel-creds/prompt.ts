export const ASK_USER_PROMPT_EVENT = "rpiv:ask-user:prompt" as const;
export const ASK_USER_BLOCKED_EVENT = "rpiv:ask-user:blocked" as const;

const RESERVED_LABELS = new Set(["Other", "Type something."]);
const MAX_DETAIL_CHARS = 4000;
const MAX_DETAIL_LINES = 100;

export interface SentinelPromptOption {
  label: string;
  description: string;
}

export interface SentinelPrompt {
  header: string;
  question: string;
  details: string;
  options: ReadonlyArray<SentinelPromptOption>;
}

export interface AskUserPromptPayload {
  questions: ReadonlyArray<{
    question: string;
    header: string;
    multiSelect: false;
    options: ReadonlyArray<SentinelPromptOption & { hasPreview: false }>;
  }>;
}

interface PromptEventBus {
  emit(channel: string, payload: unknown): void;
}

export function createSentinelPrompt(input: SentinelPrompt): SentinelPrompt {
  if (input.header.trim().length === 0 || input.header.length > 16) {
    throw new Error("Sentinel prompt header must be 1-16 characters");
  }
  if (!input.question.trim().endsWith("?")) {
    throw new Error("Sentinel prompt question must end with '?'");
  }
  if (input.options.length < 2 || input.options.length > 4) {
    throw new Error("Sentinel prompt requires 2-4 options");
  }

  const labels = new Set<string>();
  for (const option of input.options) {
    if (option.label.trim().length === 0 || option.description.trim().length === 0) {
      throw new Error("Sentinel prompt options require labels and descriptions");
    }
    if (RESERVED_LABELS.has(option.label) || labels.has(option.label)) {
      throw new Error(`Invalid or duplicate sentinel prompt option: ${option.label}`);
    }
    labels.add(option.label);
  }

  return {
    header: input.header,
    question: input.question,
    details: input.details,
    options: input.options.map((option) => ({ ...option })),
  };
}

export function buildPromptPayload(prompt: SentinelPrompt): AskUserPromptPayload {
  return {
    questions: [
      {
        question: prompt.question,
        header: prompt.header,
        multiSelect: false,
        options: prompt.options.map((option) => ({
          label: option.label,
          description: option.description,
          hasPreview: false,
        })),
      },
    ],
  };
}

export function formatPromptTitle(prompt: SentinelPrompt): string {
  const details = sanitizePromptDetails(prompt.details).trim();
  const options = prompt.options.map((option) => `${option.label} — ${option.description}`).join("\n");
  return [`[sentinel-creds] ${prompt.header}`, details, prompt.question, options]
    .filter(Boolean)
    .join("\n\n");
}

export async function runPromptLifecycle<T>(
  events: PromptEventBus,
  prompt: SentinelPrompt,
  wait: () => Promise<T>,
): Promise<T> {
  emitSafely(events, ASK_USER_PROMPT_EVENT, buildPromptPayload(prompt));
  emitSafely(events, ASK_USER_BLOCKED_EVENT, { active: true });
  try {
    return await wait();
  } finally {
    emitSafely(events, ASK_USER_BLOCKED_EVENT, { active: false });
  }
}

function sanitizePromptDetails(details: string): string {
  const sanitized = details
    .replace(/\u001b\][\s\S]*?(?:\u0007|\u001b\\)/g, "")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\r\n?/g, "\n")
    .replace(/\t/g, "  ")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "")
    .replace(/\u001b/g, "");
  const lines = sanitized.split("\n").slice(0, MAX_DETAIL_LINES).join("\n");
  return lines.length > MAX_DETAIL_CHARS
    ? `${lines.slice(0, MAX_DETAIL_CHARS - 1)}…`
    : lines;
}

function emitSafely(events: PromptEventBus, channel: string, payload: unknown): void {
  try {
    events.emit(channel, payload);
  } catch {
    // Observers must not disable a security prompt.
  }
}
