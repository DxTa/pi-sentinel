/**
 * Session-scoped sandbox host fallbacks and yolo ask patterns. In memory only;
 * cleared on session shutdown. Consumers merge these with their config lists.
 */
const hostFallbackCommands = new Set<string>();
const yoloAskPatterns = new Set<string>();

export function setSessionHostFallback(prefix: string, present: boolean): void {
  if (present) hostFallbackCommands.add(prefix);
  else hostFallbackCommands.delete(prefix);
}

export function setSessionYoloAskPattern(pattern: string, present: boolean): void {
  if (present) yoloAskPatterns.add(pattern);
  else yoloAskPatterns.delete(pattern);
}

export function getSessionHostFallbacks(): string[] {
  return [...hostFallbackCommands];
}

export function getSessionYoloAskPatterns(): string[] {
  return [...yoloAskPatterns];
}

export function clearSessionLists(): void {
  hostFallbackCommands.clear();
  yoloAskPatterns.clear();
}
