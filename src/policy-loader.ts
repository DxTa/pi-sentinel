import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

import { extractFrontmatter, parseSimpleYamlMap, toRecord } from "./common";
import {
  loadUnifiedConfig,
  normalizeUnifiedConfig,
  stripJsonComments,
} from "./config-loader";
import {
  getBundledConfigPath,
  getGlobalConfigPath,
} from "./config-paths";
import { EXTENSION_ROOT } from "./extension-config";
import { mergeFlatPermissions } from "./permission-merge";
import {
  getSecurityProfileStamp,
  loadActiveSecurityProfilePermission,
} from "./security-profile-loader";
import type { ScopeConfig } from "./types";

// ---------------------------------------------------------------------------
// File-stamp helper
// ---------------------------------------------------------------------------

function getFileStamp(path: string): string {
  try {
    return String(statSync(path).mtimeMs);
  } catch {
    return "missing";
  }
}

// ---------------------------------------------------------------------------
// MCP server-name reading helpers
// ---------------------------------------------------------------------------

function readConfiguredMcpServerNamesFromConfigPath(
  configPath: string,
): string[] {
  try {
    const raw = readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(stripJsonComments(raw)) as unknown;
    const root = toRecord(parsed);
    const serverRecord = toRecord(root.mcpServers ?? root["mcp-servers"]);

    return Object.keys(serverRecord)
      .map((name) => name.trim())
      .filter((name) => name.length > 0);
  } catch {
    return [];
  }
}

function getConfiguredMcpServerNamesFromPaths(
  paths: readonly string[],
): string[] {
  const seen = new Set<string>();

  for (const path of paths) {
    for (const name of readConfiguredMcpServerNamesFromConfigPath(path)) {
      seen.add(name);
    }
  }

  return [...seen].sort(
    (left, right) => right.length - left.length || left.localeCompare(right),
  );
}

// ---------------------------------------------------------------------------
// Resolved policy paths
// ---------------------------------------------------------------------------

export interface ResolvedPolicyPaths {
  bundledConfigPath: string;
  bundledConfigExists: boolean;
  globalConfigPath: string;
  globalConfigExists: boolean;
  projectConfigPath: string | null;
  projectConfigExists: boolean;
  agentsDir: string;
  agentsDirExists: boolean;
  projectAgentsDir: string | null;
  projectAgentsDirExists: boolean;
}

// ---------------------------------------------------------------------------
// PolicyLoader interface
// ---------------------------------------------------------------------------

/**
 * Abstraction over file I/O for loading permission policy from disk.
 * Implementations handle caching, path resolution, and config-issue
 * accumulation.  `PermissionManager` depends on this interface so that
 * merge + evaluation logic can be tested with an in-memory stub.
 */
export interface PolicyLoader {
  loadBundledConfig?(): ScopeConfig;
  loadGlobalConfig(): ScopeConfig;
  loadProjectConfig(): ScopeConfig;
  loadAgentConfig(agentName?: string): ScopeConfig;
  loadProjectAgentConfig(agentName?: string): ScopeConfig;
  loadSecurityProfileConfig(): ScopeConfig;
  getConfiguredMcpServerNames(): readonly string[];
  /** Combined mtime stamp for cache invalidation. */
  getCacheStamp(agentName?: string): string;
  /** Accumulated config-parse issues across all loads. */
  getConfigIssues(): string[];
  /** Resolved paths for the /sentinel show command. */
  getResolvedPolicyPaths(): ResolvedPolicyPaths;
}

// ---------------------------------------------------------------------------
// Default path factories (deferred until call-time, not module scope)
// ---------------------------------------------------------------------------

function defaultGlobalConfigPath(): string {
  return getGlobalConfigPath(getAgentDir());
}
function defaultAgentsDir(): string {
  return join(getAgentDir(), "agents");
}
function defaultGlobalMcpConfigPath(): string {
  return join(getAgentDir(), "mcp.json");
}

// ---------------------------------------------------------------------------
// File cache helper type
// ---------------------------------------------------------------------------

type FileCacheEntry<TValue> = {
  stamp: string;
  value: TValue;
};

// ---------------------------------------------------------------------------
// Options shared between FilePolicyLoader and the backward-compat
// PermissionManager constructor.
// ---------------------------------------------------------------------------

export interface PolicyLoaderOptions {
  bundledConfigPath?: string;
  globalConfigPath?: string;
  agentsDir?: string;
  projectGlobalConfigPath?: string;
  projectAgentsDir?: string;
  globalMcpConfigPath?: string;
  mcpServerNames?: readonly string[];
}

// ---------------------------------------------------------------------------
// FilePolicyLoader — the production implementation
// ---------------------------------------------------------------------------

/**
 * Production `PolicyLoader` that reads config files from disk with
 * mtime-based caching.
 */
export class FilePolicyLoader implements PolicyLoader {
  private readonly bundledConfigPath: string;
  private readonly globalConfigPath: string;
  private readonly agentsDir: string;
  private readonly projectGlobalConfigPath: string | null;
  private readonly projectAgentsDir: string | null;
  private readonly globalMcpConfigPath: string;
  private readonly configuredMcpServerNamesOverride: readonly string[] | null;

  private bundledConfigCache: FileCacheEntry<ScopeConfig> | null = null;
  private globalConfigCache: FileCacheEntry<ScopeConfig> | null = null;
  private projectGlobalConfigCache: FileCacheEntry<ScopeConfig> | null = null;
  private readonly agentConfigCache = new Map<
    string,
    FileCacheEntry<ScopeConfig>
  >();
  private readonly projectAgentConfigCache = new Map<
    string,
    FileCacheEntry<ScopeConfig>
  >();
  private configuredMcpServerNamesCache: FileCacheEntry<
    readonly string[]
  > | null = null;
  private accumulatedConfigIssues: string[] = [];

  constructor(options: PolicyLoaderOptions = {}) {
    this.bundledConfigPath =
      options.bundledConfigPath ?? getBundledConfigPath(EXTENSION_ROOT);
    this.globalConfigPath =
      options.globalConfigPath ?? defaultGlobalConfigPath();
    this.agentsDir = options.agentsDir ?? defaultAgentsDir();
    this.projectGlobalConfigPath = options.projectGlobalConfigPath ?? null;
    this.projectAgentsDir = options.projectAgentsDir ?? null;
    this.globalMcpConfigPath =
      options.globalMcpConfigPath ?? defaultGlobalMcpConfigPath();
    this.configuredMcpServerNamesOverride = options.mcpServerNames
      ? [
          ...new Set(
            options.mcpServerNames
              .map((name) => name.trim())
              .filter((name) => name.length > 0),
          ),
        ]
      : null;
  }

  // ── Config issue accumulation ────────────────────────────────────────

  private accumulateConfigIssues(issues: string[]): void {
    for (const issue of issues) {
      if (!this.accumulatedConfigIssues.includes(issue)) {
        this.accumulatedConfigIssues.push(issue);
      }
    }
  }

  getConfigIssues(): string[] {
    return [...this.accumulatedConfigIssues];
  }

  // ── Scope loaders ────────────────────────────────────────────────────

  private loadPermissionConfigPaths(paths: ReadonlyArray<string | null>): ScopeConfig {
    let permission: ScopeConfig["permission"];

    for (const path of paths) {
      if (!path || !existsSync(path)) continue;
      const { config, issues } = loadUnifiedConfig(path);
      this.accumulateConfigIssues(issues);
      if (config.permission) {
        permission = permission
          ? mergeFlatPermissions(permission, config.permission)
          : config.permission;
      }
    }

    return { permission };
  }

  loadBundledConfig(): ScopeConfig {
    const stamp = getFileStamp(this.bundledConfigPath);
    if (this.bundledConfigCache?.stamp === stamp) {
      return this.bundledConfigCache.value;
    }

    const value = this.loadPermissionConfigPaths([this.bundledConfigPath]);
    this.bundledConfigCache = { stamp, value };
    return value;
  }

  loadGlobalConfig(): ScopeConfig {
    const stamp = getFileStamp(this.globalConfigPath);
    if (this.globalConfigCache?.stamp === stamp) {
      return this.globalConfigCache.value;
    }

    const value = this.loadPermissionConfigPaths([this.globalConfigPath]);

    this.globalConfigCache = { stamp, value };
    return value;
  }

  loadProjectConfig(): ScopeConfig {
    const stamp = getFileStamp(this.projectGlobalConfigPath ?? "");
    if (this.projectGlobalConfigCache?.stamp === stamp) {
      return this.projectGlobalConfigCache.value;
    }

    const value = this.loadPermissionConfigPaths([this.projectGlobalConfigPath]);

    this.projectGlobalConfigCache = { stamp, value };
    return value;
  }

  private loadScopeConfigFrom(
    dir: string | null,
    cache: Map<string, FileCacheEntry<ScopeConfig>>,
    agentName?: string,
  ): ScopeConfig {
    if (!dir || !agentName) {
      return {};
    }

    const filePath = join(dir, `${agentName}.md`);
    const stamp = getFileStamp(filePath);
    const cached = cache.get(agentName);
    if (cached?.stamp === stamp) {
      return cached.value;
    }

    let value: ScopeConfig;
    try {
      const markdown = readFileSync(filePath, "utf-8");
      const frontmatter = extractFrontmatter(markdown);
      if (!frontmatter) {
        value = {};
      } else {
        const parsed = parseSimpleYamlMap(frontmatter);
        const { config, issues } = normalizeUnifiedConfig(parsed);
        this.accumulateConfigIssues(issues);
        value = { permission: config.permission };
      }
    } catch {
      value = {};
    }

    cache.set(agentName, { stamp, value });
    return value;
  }

  loadAgentConfig(agentName?: string): ScopeConfig {
    return this.loadScopeConfigFrom(
      this.agentsDir,
      this.agentConfigCache,
      agentName,
    );
  }

  loadProjectAgentConfig(agentName?: string): ScopeConfig {
    return this.loadScopeConfigFrom(
      this.projectAgentsDir,
      this.projectAgentConfigCache,
      agentName,
    );
  }

  loadSecurityProfileConfig(): ScopeConfig {
    const profile = loadActiveSecurityProfilePermission(this.bundledConfigPath);
    this.accumulateConfigIssues(profile.issues);
    return { permission: profile.permission };
  }

  // ── MCP server names ─────────────────────────────────────────────────

  getConfiguredMcpServerNames(): readonly string[] {
    if (this.configuredMcpServerNamesOverride) {
      return this.configuredMcpServerNamesOverride;
    }

    const paths = [this.globalMcpConfigPath];
    const stamp = paths
      .map((path) => `${path}:${getFileStamp(path)}`)
      .join("|");
    if (this.configuredMcpServerNamesCache?.stamp === stamp) {
      return this.configuredMcpServerNamesCache.value;
    }

    const value = getConfiguredMcpServerNamesFromPaths(paths);
    this.configuredMcpServerNamesCache = { stamp, value };
    return value;
  }

  // ── Cache stamp ───────────────────────────────────────────────────────

  getCacheStamp(agentName?: string): string {
    const agentStamp = agentName
      ? getFileStamp(join(this.agentsDir, `${agentName}.md`))
      : "missing";
    const projectStamp = this.projectGlobalConfigPath
      ? getFileStamp(this.projectGlobalConfigPath)
      : "none";
    const projectAgentStamp =
      this.projectAgentsDir && agentName
        ? getFileStamp(join(this.projectAgentsDir, `${agentName}.md`))
        : "none";

    return `${getFileStamp(this.bundledConfigPath)}|${getFileStamp(this.globalConfigPath)}|${getSecurityProfileStamp(this.bundledConfigPath)}|${projectStamp}|${agentStamp}|${projectAgentStamp}`;
  }

  // ── Resolved paths ────────────────────────────────────────────────────

  getResolvedPolicyPaths(): ResolvedPolicyPaths {
    return {
      bundledConfigPath: this.bundledConfigPath,
      bundledConfigExists: existsSync(this.bundledConfigPath),
      globalConfigPath: this.globalConfigPath,
      globalConfigExists: existsSync(this.globalConfigPath),
      projectConfigPath: this.projectGlobalConfigPath,
      projectConfigExists: this.projectGlobalConfigPath
        ? existsSync(this.projectGlobalConfigPath)
        : false,
      agentsDir: this.agentsDir,
      agentsDirExists: existsSync(this.agentsDir),
      projectAgentsDir: this.projectAgentsDir,
      projectAgentsDirExists: this.projectAgentsDir
        ? existsSync(this.projectAgentsDir)
        : false,
    };
  }
}
