/**
 * External path gate for sandbox.
 *
 * Detects paths referenced in bash commands that exist on the host but would
 * be invisible inside the current sandbox contract (outside repo root, cwd,
 * configured binds, and backend-default visible scopes). When detected, the
 * user is prompted to grant read-only access.
 */

import { homedir } from "node:os";
import { resolve, isAbsolute } from "node:path";
import { existsSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";
import { validateSandboxGrantPath } from "./settings.js";
import { canonicalPath, createSandboxVisibilityMatcher, expandHomePath } from "./sandbox-visible-paths.js";

export function resolveRepoRoot(cwd: string): string {
  try {
    const result = spawnSync(
      "git",
      ["-C", cwd, "rev-parse", "--show-toplevel"],
      {
        encoding: "utf-8",
        timeout: 5000,
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    const root = result.stdout?.trim();
    if (result.status === 0 && root) return root;
  } catch {
    // ignore
  }
  return cwd;
}

export function extractPathTokens(command: string): string[] {
  // Expand common env vars before tokenising so $HOME/dev/… is caught.
  const expandedCmd = command
    .replace(/\$HOME\b/g, homedir())
    .replace(/\$\{HOME\}/g, homedir());

  const tokens = expandedCmd
    .split(/[\s;|&<>()`$\\'"!\n\r\t]+/)
    .filter((t) => t.length > 0 && !t.startsWith("-"));

  const paths: string[] = [];
  for (const token of tokens) {
    // --flag=/path or --flag=~/path
    const eqIdx = token.indexOf("=");
    if (eqIdx > 0) {
      const afterEq = token.slice(eqIdx + 1);
      if (
        afterEq.startsWith("/") ||
        afterEq.startsWith("~") ||
        afterEq.startsWith("./") ||
        afterEq.startsWith("../")
      ) {
        paths.push(afterEq);
        continue;
      }
    }

    if (
      token.startsWith("/") ||
      token.startsWith("~") ||
      token.startsWith("./") ||
      token.startsWith("../") ||
      (!token.startsWith("-") && token.includes("/"))
    ) {
      paths.push(token);
    }
  }
  return [...new Set(paths)];
}

export interface ExternalPathInfo {
  /** Absolute path on host. */
  path: string;
  /** Whether it's a directory. */
  isDirectory: boolean;
  /** Human-friendly path (preserves ~ if present). */
  displayPath: string;
}

export function detectExternalPaths(
  command: string,
  cwd: string,
  profile: ResolvedSandboxProfile,
  config?: SandboxConfig,
  repoRootResolver: (cwd: string) => string = resolveRepoRoot,
  ignoredPaths: readonly string[] = [],
): ExternalPathInfo[] {
  const repoRoot = repoRootResolver(cwd);
  const isVisible = createSandboxVisibilityMatcher({ repoRoot, cwd, profile, config });
  const tokens = extractPathTokens(command);
  const ignored = new Set(ignoredPaths.map(canonicalPath));
  const externals: ExternalPathInfo[] = [];

  for (const raw of tokens) {
    const expanded = expandHomePath(raw);
    const absPath = isAbsolute(expanded)
      ? resolve(expanded)
      : resolve(cwd, expanded);

    if (!existsSync(absPath)) continue;
    const canonical = canonicalPath(absPath);
    if (isVisible(canonical) || ignored.has(canonical)) continue;
    if (externals.some((e) => e.path === canonical)) continue;

    validateSandboxGrantPath(canonical);
    const stat = statSync(canonical);
    externals.push({
      path: canonical,
      isDirectory: stat.isDirectory(),
      displayPath: raw.startsWith("~") ? raw : absPath,
    });
  }
  return externals;
}

export function formatExternalPathPrompt(
  paths: ExternalPathInfo[],
  command: string,
): string {
  const maxCmd = 80;
  const truncated =
    command.length > maxCmd ? command.slice(0, maxCmd - 3) + "..." : command;
  const lines = paths.map(
    (p) => `  • ${p.displayPath}${p.isDirectory ? " (directory)" : ""}`,
  );
  return (
    `Paths outside workspace sandbox scope:\n${lines.join("\n")}\n\n` +
    `Command: ${truncated}\n\n` +
    `Without access the sandbox sees "No such file or directory". ` +
    `Grant read-only visibility?`
  );
}
