import { closeSync, fchmodSync, openSync, writeFileSync } from "node:fs";

import { redactSecrets } from "./sentinel-creds/scanner";

import {
  EXTENSION_ID,
  type PermissionSystemExtensionConfig,
} from "./extension-config";

const SENSITIVE_ASSIGNMENT = /\b([A-Z_][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIALS?|AUTH(?:ORIZATION)?|API[_-]?KEY|PRIVATE[_-]?KEY)[A-Z0-9_]*)\s*=\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s;&|]+)/gi;

function redactLogString(value: string): string {
  return redactSecrets(value).replace(SENSITIVE_ASSIGNMENT, "$1=[REDACTED]");
}

export function safeJsonStringify(value: unknown, redactStrings = false): string | undefined {
  const seen = new WeakSet<object>();
  return JSON.stringify(value, (_key, currentValue) => {
    if (currentValue instanceof Error) {
      return {
        name: currentValue.name,
        message: currentValue.message,
        stack: currentValue.stack,
      };
    }

    if (typeof currentValue === "bigint") {
      return currentValue.toString();
    }

    if (typeof currentValue === "string" && redactStrings) {
      return redactLogString(currentValue);
    }

    if (typeof currentValue === "object" && currentValue !== null) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument -- JSON.stringify replacer receives any; currentValue is narrowed to object here
      if (seen.has(currentValue)) {
        return "[Circular]";
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument -- same as above
      seen.add(currentValue);
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- JSON.stringify replacer must return any
    return currentValue;
  });
}

export interface PermissionSystemLogger {
  debug: (
    event: string,
    details?: Record<string, unknown>,
  ) => string | undefined;
  review: (
    event: string,
    details?: Record<string, unknown>,
  ) => string | undefined;
}

interface PermissionSystemLoggerOptions {
  getConfig: () => PermissionSystemExtensionConfig;
  debugLogPath: string;
  reviewLogPath: string;
  ensureLogsDirectory: () => string | undefined;
}

export function createPermissionSystemLogger(
  options: PermissionSystemLoggerOptions,
): PermissionSystemLogger {
  const { debugLogPath, reviewLogPath, ensureLogsDirectory } = options;

  const writeLine = (
    stream: "debug" | "review",
    path: string,
    event: string,
    details: Record<string, unknown>,
  ): string | undefined => {
    const directoryError = ensureLogsDirectory();
    if (directoryError) {
      return directoryError;
    }

    try {
      const line = safeJsonStringify({
        timestamp: new Date().toISOString(),
        extension: EXTENSION_ID,
        stream,
        event,
        ...details,
      }, true);
      if (!line) {
        return `Failed to write pi-sentinel ${stream} log '${path}': event could not be serialized.`;
      }
      const fd = openSync(path, "a", 0o600);
      try {
        fchmodSync(fd, 0o600);
        writeFileSync(fd, `${line}\n`, "utf-8");
      } finally {
        closeSync(fd);
      }
      return undefined;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return `Failed to write pi-sentinel ${stream} log '${path}': ${message}`;
    }
  };

  const debug = (
    event: string,
    details: Record<string, unknown> = {},
  ): string | undefined => {
    if (!options.getConfig().debugLog) {
      return undefined;
    }

    const config = options.getConfig();
    return writeLine("debug", debugLogPath, event, {
      ...details,
      mode: config.mode,
    });
  };

  const review = (
    event: string,
    details: Record<string, unknown> = {},
  ): string | undefined => {
    if (!options.getConfig().permissionReviewLog) {
      return undefined;
    }

    return writeLine("review", reviewLogPath, event, details);
  };

  return { debug, review };
}
