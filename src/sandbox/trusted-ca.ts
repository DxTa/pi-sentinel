import { realpathSync } from "node:fs";
import { isAbsolute } from "node:path";

import { DEFAULT_MASKED_PATTERNS, isPathMasked } from "./masked-file-gate.js";

export function trustedCaFile(value: string | undefined, maskedPaths: readonly string[]): { value: string; path: string } | undefined {
  if (!value || !isAbsolute(value)) return undefined;
  try {
    const path = realpathSync(value);
    const masks = [...DEFAULT_MASKED_PATTERNS, ...maskedPaths].filter((pattern) => pattern !== "**/*.pem");
    if (isPathMasked(value, masks) || isPathMasked(path, masks)) return undefined;
    return { value, path };
  } catch {
    return undefined;
  }
}
