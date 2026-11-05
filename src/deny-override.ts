import { homedir } from "node:os";
import { isProtectedCredentialWritePath } from "./protected-read";
import { isForbiddenWritePath } from "./yolo-forbidden-paths";

// Tool calls whose policy deny a person overrode; the sandbox gate takes one once.
const overridden = new Set<string>();

export function markDenyOverride(toolCallId: string): void {
  overridden.add(toolCallId);
}

export function takeDenyOverride(toolCallId: string | undefined): boolean {
  return toolCallId !== undefined && overridden.delete(toolCallId);
}

/** System and credential paths keep their separate sandbox prompt even after a policy override. */
export function canAutoGrantOverride(paths: readonly string[], cwd: string): boolean {
  return paths.every((path) => !isForbiddenWritePath(path, homedir()) && !isProtectedCredentialWritePath(path, cwd));
}
