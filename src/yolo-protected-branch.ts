import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import { bashInnerCommands, bashWords } from "./bash-segments";
import { gitPushParts, isGitPushWords } from "./yolo-mode";

/* shortcut: protects main, master and the remote's HEAD branch by name; host branch-protection rules are not read. */
const PROTECTED_NAMES = ["main", "master"];
const ALL_BRANCH_FLAGS = new Set(["--all", "--branches", "--mirror"]);
/* Push options that take the next word as their value. */
const PUSH_VALUE_OPTIONS = new Set(["--repo", "--receive-pack", "--exec", "-o", "--push-option"]);

function git(dir: string, args: string[]): string | null {
  try {
    const out = execFileSync("git", ["-C", dir, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
    });
    return out.trim() || null;
  } catch {
    return null;
  }
}

function pushPositionals(args: string[]): string[] {
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (PUSH_VALUE_OPTIONS.has(arg)) i++;
    else if (!arg.startsWith("-")) positionals.push(arg);
  }
  return positionals;
}

/* Branch a refspec `[+]src[:dst]` writes on the remote; null for non-branch refs such as tags. */
function destinationBranch(refspec: string, currentBranch: string | null): string | null {
  const spec = refspec.replace(/^\+/, "");
  const colon = spec.indexOf(":");
  const name = colon === -1 ? spec : spec.slice(colon + 1);
  if (name === "HEAD") return currentBranch;
  if (name.startsWith("refs/heads/")) return name.slice("refs/heads/".length);
  return name.startsWith("refs/") ? null : name;
}

/**
 * Reason to block a git push that writes the default branch or every branch, or null when it may run.
 * An unresolvable target blocks only when `blockUnresolved` is set (yolo, which never prompts).
 */
export function protectedPushReason(command: string, cwd: string, blockUnresolved: boolean): string | null {
  for (const part of bashInnerCommands(command)?.commands ?? [command]) {
    const words = bashWords(part);
    if (!words || !isGitPushWords(words)) continue;

    const { dir, args } = gitPushParts(words);
    if (args.some((arg) => /[$`]/.test(arg))) {
      if (blockUnresolved) return "yolo mode cannot tell which branch this push writes, so it blocks it";
      continue;
    }
    if (args.some((arg) => ALL_BRANCH_FLAGS.has(arg))) return "git push blocked: it writes every branch, including the default branch";

    const repo = resolve(cwd, dir ?? ".");
    const positionals = pushPositionals(args);
    const remote = positionals[0] ?? "origin";
    const currentBranch = git(repo, ["symbolic-ref", "-q", "--short", "HEAD"]);
    const remoteHead = git(repo, ["symbolic-ref", "--short", `refs/remotes/${remote}/HEAD`]);
    const defaultBranch = remoteHead?.startsWith(`${remote}/`) ? remoteHead.slice(remote.length + 1) : null;
    const protectedNames = new Set([...PROTECTED_NAMES, defaultBranch]);

    const targets = positionals.length > 1
      ? positionals.slice(1).map((refspec) => destinationBranch(refspec, currentBranch))
      : [currentBranch];
    const hit = targets.find((name) => name !== null && protectedNames.has(name));
    if (hit) return `git push blocked: it writes the default branch "${hit}"`;
  }
  return null;
}
