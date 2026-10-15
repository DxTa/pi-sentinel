/**
 * External path gate for sandbox.
 *
 * Detects paths referenced in bash commands that exist on the host but would
 * be invisible inside the current sandbox contract (outside repo root, cwd,
 * configured binds, and backend-default visible scopes). When detected, the
 * reads stay read-only; literal external output redirects require approved write access.
 */

import { homedir } from "node:os";
import { dirname, isAbsolute, resolve } from "node:path";
import { existsSync, lstatSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import type { ResolvedSandboxProfile, SandboxConfig } from "./types.js";
import { DEFAULT_MASKED_PATTERNS, isPathMasked } from "./masked-file-gate.js";
import { isPathWithinDirectory } from "#src/path-utils";
import { extractExternalWritePathsFromBashCommand, extractTokensForPathRules } from "../handlers/gates/bash-path-extractor.js";
import { resolveSandboxBindPaths, validateSandboxGrantPath } from "./settings.js";
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
    // Slash-only tokens (// comments in heredocs/code) are never path arguments.
    if (/^\/{2,}$/.test(token)) continue;
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

export async function detectExternalPaths(
  command: string,
  cwd: string,
  profile: ResolvedSandboxProfile,
  config?: SandboxConfig,
  repoRootResolver: (cwd: string) => string = resolveRepoRoot,
  ignoredPaths: readonly string[] = [],
): Promise<ExternalPathInfo[]> {
  const repoRoot = repoRootResolver(cwd);
  const isVisible = createSandboxVisibilityMatcher({ repoRoot, cwd, profile, config });
  const expandedCommand = command
    .replace(/\$HOME\b/g, homedir())
    .replace(/\$\{HOME\}/g, homedir());
  const tokens = await extractTokensForPathRules(expandedCommand);
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

export async function detectExternalWritePaths(
  command: string,
  cwd: string,
  profile: ResolvedSandboxProfile,
  config?: SandboxConfig,
  repoRootResolver: (cwd: string) => string = resolveRepoRoot,
): Promise<ExternalPathInfo[]> {
  const repoRoot = repoRootResolver(cwd);
  const writableRoots = [
    cwd,
    repoRoot,
    ...resolveSandboxBindPaths(
      [...(config?.rwBinds ?? []), ...(profile.rwBinds ?? [])],
      repoRoot,
    ),
  ].map((root) => canonicalPath(root));
  const paths: ExternalPathInfo[] = [];

  for (const candidate of await extractExternalWritePathsFromBashCommand(command, cwd)) {
    const canonical = canonicalPath(candidate);
    const targetExists = existsSync(canonical);
    if (isPathMasked(canonical, [...DEFAULT_MASKED_PATTERNS, ...(profile.maskedPaths ?? [])])) {
      if (!targetExists) throw new Error("Refusing masked external write target: " + canonical);
      continue;
    }
    if (writableRoots.some((root) => canonical === root || isPathWithinDirectory(canonical, root))) {
      continue;
    }
    validateSandboxGrantPath(canonical);

    if (!targetExists) {
      let parent = dirname(canonical);
      while (!existsSync(parent)) {
        try {
          if (lstatSync(parent).isSymbolicLink()) {
            throw new Error("Refusing unresolved symlink in external write target: " + parent);
          }
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
        }
        const nextParent = dirname(parent);
        if (nextParent === parent) {
          throw new Error("Could not find existing parent for external write target: " + canonical);
        }
        parent = nextParent;
      }

      const canonicalParent = canonicalPath(parent);
      if (!statSync(canonicalParent).isDirectory()) {
        throw new Error("External write target parent is not a directory: " + canonicalParent);
      }
      validateSandboxGrantPath(canonicalParent);
      if (!paths.some((entry) => entry.path === canonicalParent)) {
        paths.push({ path: canonicalParent, isDirectory: true, displayPath: canonicalParent });
      }
      continue;
    }

    const stat = statSync(canonical);
    if (!stat.isFile() || paths.some((entry) => entry.path === canonical)) continue;
    paths.push({ path: canonical, isDirectory: false, displayPath: canonical });
  }

  return paths;
}

export function formatExternalPathPrompt(
  paths: ExternalPathInfo[],
  command: string,
  mode: "ro" | "rw" = "ro",
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
    `Grant ${mode === "rw" ? "read-write access" : "read-only visibility"}?`
  );
}
