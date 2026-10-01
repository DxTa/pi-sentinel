import { join, resolve, sep } from "node:path";
import { canonicalPath } from "./sandbox/sandbox-visible-paths.js";

const SYSTEM_ROOTS = ["/etc", "/System", "/Library", "/usr", "/bin", "/sbin", "/private"];
const CANONICAL_SYSTEM_ROOTS = SYSTEM_ROOTS.map(canonicalPath);



/** System roots always prompt in yolo-auto, regardless of model output. */
export function isSensitivePath(absPath: string, homeDir: string): boolean {
  const homeLibrary = join(homeDir, "Library");
  const lexicalRoots = [...SYSTEM_ROOTS, homeLibrary];
  const canonicalRoots = [...CANONICAL_SYSTEM_ROOTS, canonicalPath(homeLibrary)];
  return isWithinAnyRoot(resolve(absPath), lexicalRoots)
    || isWithinAnyRoot(canonicalPath(absPath), canonicalRoots);
}

function isWithinAnyRoot(target: string, roots: readonly string[]): boolean {
  return roots.some((root) => target === root || target.startsWith(root + sep));
}
