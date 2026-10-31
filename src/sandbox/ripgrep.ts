import { accessSync, constants } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

let cachedBundledPath: string | null | undefined;

/**
 * Path to the ripgrep binary shipped by `@vscode/ripgrep`, or null when the
 * platform package is not installed. Linux SRT runs ripgrep on the host to find
 * files it must write-protect; bundling it removes the system `rg` requirement.
 */
export function bundledRipgrepPath(): string | null {
  if (cachedBundledPath !== undefined) return cachedBundledPath;
  cachedBundledPath = null;
  try {
    const { rgPath } = require("@vscode/ripgrep") as { rgPath: string };
    accessSync(rgPath, constants.X_OK);
    cachedBundledPath = rgPath;
  } catch {
    // No prebuilt binary for this platform: fall back to `rg` on PATH.
  }
  return cachedBundledPath;
}

/** Ripgrep command for SRT: the bundled binary, else `rg` from PATH. */
export function ripgrepCommand(): string {
  return bundledRipgrepPath() ?? "rg";
}
