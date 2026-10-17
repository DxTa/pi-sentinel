import { realpathSync } from "node:fs";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";

import { canonicalPath } from "./sandbox/sandbox-visible-paths.js";

const SYSTEM_ROOTS = ["/etc", "/System", "/Library", "/usr", "/bin", "/sbin", "/private/etc", "/private/var", "/var"];
/* Tools and macOS itself write here, so these stay open inside a forbidden root. */
const TEMP_AND_LOCAL = ["/usr/local", "/var/folders", "/private/var/folders", "/var/tmp", "/private/var/tmp"];
const CREDENTIAL_DIRS = [".ssh", ".aws", ".gnupg"];

const within = (target: string, root: string): boolean => target === root || target.startsWith(root + sep);
const withinAny = (target: string, roots: readonly string[]): boolean => roots.some((root) => within(target, root));
const withCanonical = (roots: readonly string[]): string[] => [...roots, ...roots.map(canonicalPath)];

/* Resolve symlinks component by component, so a `..` after a symlink steps out of the link's target. */
function physicalPath(absPath: string): string {
  let current = "/";
  for (const part of absPath.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      current = dirname(current);
      continue;
    }
    const next = join(current, part);
    try {
      current = realpathSync.native(next);
    } catch {
      current = next;
    }
  }
  return current;
}

/**
 * Paths `yolo` mode never writes: system roots and credential folders. A symlink that
 * leads into one counts too, because both the written path and its target are checked.
 */
export function isForbiddenWritePath(absPath: string, homeDir: string): boolean {
  const forbidden = withCanonical([...SYSTEM_ROOTS, ...CREDENTIAL_DIRS.map((dir) => join(homeDir, dir))]);
  const open = withCanonical(TEMP_AND_LOCAL);
  const absolute = isAbsolute(absPath) ? absPath : resolve(absPath);
  return [resolve(absolute), physicalPath(absolute)].some(
    (candidate) => withinAny(candidate, forbidden) && !withinAny(candidate, open),
  );
}
