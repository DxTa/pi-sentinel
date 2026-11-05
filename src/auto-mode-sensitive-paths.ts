import { join, resolve, sep } from "node:path";
import { canonicalPath } from "./sandbox/sandbox-visible-paths.js";
import { isForbiddenWritePath } from "./yolo-forbidden-paths.js";

const SYSTEM_ROOTS = ["/etc", "/System", "/Library", "/usr", "/bin", "/sbin", "/private"];
const CANONICAL_SYSTEM_ROOTS = SYSTEM_ROOTS.map(canonicalPath);



/** System roots always prompt in auto, regardless of model output. */
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

const SHELL_STARTUP_FILES = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile"];

/** Write targets the model never judges: system roots, credential folders and shell startup files. */
export function isProtectedWriteTarget(absPath: string, homeDir: string): boolean {
  return isForbiddenWritePath(absPath, homeDir)
    || SHELL_STARTUP_FILES.some((file) => resolve(absPath) === join(homeDir, file));
}
