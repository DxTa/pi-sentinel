// shortcut: keyword match, not a SQL parser. It over-matches (a search for "drop table" prompts),
// which only costs a prompt. Upgrade to a parser if MCP database prompts get noisy.
const SQL_WRITE = /\b(?:drop|truncate|alter|grant|revoke)\s+\w|\bdelete\s+from\b|\binsert\s+into\b|\bupdate\s+\S+\s+set\b|\bcreate\s+(?:or\s+replace\s+)?\w|\bmerge\s+into\b/i;

/** True when any string in MCP arguments holds a SQL write or schema change; such calls skip auto mode. */
export function mcpArgsHaveSqlWrite(args: unknown, depth = 0): boolean {
  if (typeof args === "string") return SQL_WRITE.test(args);
  if (depth > 8 || !args || typeof args !== "object") return false;
  return Object.values(args).some((value) => mcpArgsHaveSqlWrite(value, depth + 1));
}
