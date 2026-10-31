/** Ordered output labels for the pinned Lion Warden revision. */
export const AUTO_MODE_LABEL_SCHEMA = {
  injection: ["benign", "injection"],
  routing: ["benign_conv", "code_development_request", "data_analytics_request", "office_request", "tool_operation_request"],
  sensitive_document: ["legal", "hr", "finance", "internal_and_tech", "source_code", "marketing", "other", "education", "medical"],
  threat: ["instruction_override", "secrets_access", "tool_abuse", "harmful_behavior", "exfiltration_attempt", "toxic_or_harmful", "benign"],
  tool_action: ["read", "write", "list", "exec", "network", "unknown"],
  tool_class: ["file", "database", "vcs", "api", "memory", "messaging", "web", "browser", "shell", "code", "system", "secrets", "infra", "unknown"],
  tool_tags: ["source:sensitive", "source:untrusted", "sink:external"],
} as const;

export type AutoModeHeadName = keyof typeof AUTO_MODE_LABEL_SCHEMA;

export function parseAutoModeLabelSchema(value: unknown): typeof AUTO_MODE_LABEL_SCHEMA {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Model label schema missing.");
  }
  const actual = value as Record<string, unknown>;
  const heads = Object.keys(AUTO_MODE_LABEL_SCHEMA) as AutoModeHeadName[];
  if (Object.keys(actual).length !== heads.length) throw new Error("Invalid model label heads.");
  for (const head of heads) {
    const labels = actual[head];
    const expected = AUTO_MODE_LABEL_SCHEMA[head];
    if (!Object.prototype.hasOwnProperty.call(actual, head)
      || !Array.isArray(labels)
      || labels.length !== expected.length
      || labels.some((label, index) => typeof label !== "string" || label !== expected[index])) {
      throw new Error("Invalid model labels: " + head);
    }
  }
  return AUTO_MODE_LABEL_SCHEMA;
}
