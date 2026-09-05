import { normalize } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

import {
  getActiveAgentName,
  getActiveAgentNameFromSystemPrompt,
} from "./active-agent";
import { toRecord } from "./common";
import { SUBAGENT_ENV_HINT_KEYS } from "./permission-forwarding";

export function normalizeFilesystemPath(pathValue: string): string {
  const normalizedPath = normalize(pathValue);
  return process.platform === "win32"
    ? normalizedPath.toLowerCase()
    : normalizedPath;
}

function isPathWithinDirectoryForSubagent(
  pathValue: string,
  directory: string,
): boolean {
  if (!pathValue || !directory) {
    return false;
  }

  if (pathValue === directory) {
    return true;
  }

  const sep = process.platform === "win32" ? "\\" : "/";
  const prefix = directory.endsWith(sep) ? directory : `${directory}${sep}`;
  return pathValue.startsWith(prefix);
}

function getContextSystemPrompt(ctx: ExtensionContext): string | undefined {
  const getSystemPrompt = toRecord(ctx).getSystemPrompt;
  if (typeof getSystemPrompt !== "function") {
    return undefined;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- SDK accessor is untyped
    const systemPrompt = getSystemPrompt.call(ctx);
    return typeof systemPrompt === "string" ? systemPrompt : undefined;
  } catch {
    return undefined;
  }
}

export function isSubagentExecutionContext(
  ctx: ExtensionContext,
  subagentSessionsDir: string,
): boolean {
  for (const key of SUBAGENT_ENV_HINT_KEYS) {
    const value = process.env[key];
    if (typeof value === "string" && value.trim()) {
      return true;
    }
  }

  const sessionDir = ctx.sessionManager.getSessionDir();
  if (!sessionDir) {
    return false;
  }

  const normalizedSessionDir = normalizeFilesystemPath(sessionDir);
  const normalizedSubagentRoot = normalizeFilesystemPath(subagentSessionsDir);
  if (
    isPathWithinDirectoryForSubagent(
      normalizedSessionDir,
      normalizedSubagentRoot,
    )
  ) {
    return true;
  }

  if (ctx.hasUI) {
    return false;
  }

  const activeAgentName =
    getActiveAgentName(ctx) ??
    getActiveAgentNameFromSystemPrompt(getContextSystemPrompt(ctx));
  return typeof activeAgentName === "string" && activeAgentName.trim().length > 0;
}
