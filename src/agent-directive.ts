// shortcut: phrase match, not a classifier. It catches text that addresses an AI agent and tells it to
// drop its instructions or permission checks; paraphrases still reach the model. Extend the lists from
// calibration misses.
const ADDRESS = /\b(?:ai|llm)\s+(?:agents?|assistants?|models?)\b|\bassistant\s*[:,]|\b(?:system|developer)\s*(?:override|prompt|message|mode)?\s*:|\bnote\s+to\s+(?:the\s+)?(?:ai|agents?|assistants?)\b/i;
const OVERRIDE = /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:previous|prior|above|earlier|system|your)?\s*(?:instructions?|rules?|prompts?|guidelines?|policy|policies)\b|\b(?:skip|disable|bypass|turn\s+off)\s+(?:all\s+|the\s+|any\s+)?(?:permission|approval|safety|security)\s*(?:checks?|prompts?|rules?)?\b|\b(?:approve|allow|accept)\s+(?:every|all|any)\s+(?:tool\s+calls?|requests?|commands?|actions?)\b|\bdeveloper\s+mode\b|\b(?:are|is)\s+(?:now\s+)?authori[sz]ed\s+to\b/i;

/** True when text tells an AI agent to drop its instructions or permission checks. Such writes skip auto mode. */
export function hasAgentDirective(text: string | undefined): boolean {
  if (!text) return false;
  return OVERRIDE.test(text) && (ADDRESS.test(text) || /\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b/i.test(text));
}
