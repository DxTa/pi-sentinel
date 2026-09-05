import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";

const CONFIG_FILENAME = "gondolin-secrets.json";
const MAX_CONFIG_BYTES = 64 * 1024;
const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;
const RESERVED_NAMES = new Set(["HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "LD_LIBRARY_PATH", "LIBRARY_PATH"]);

export interface GondolinSecretBinding {
  readonly name: string;
  readonly value: string;
  readonly hosts: readonly string[];
}

function readConfig(agentDir: string): Record<string, unknown> | undefined {
  const path = join(agentDir, CONFIG_FILENAME);
  try {
    const stats = lstatSync(path);
    if (stats.isSymbolicLink() || !stats.isFile()) throw new Error("Gondolin secret config must be a regular file.");
    if (stats.size > MAX_CONFIG_BYTES) throw new Error("Gondolin secret config is too large.");
    const value: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Gondolin secret config is invalid.");
    return value as Record<string, unknown>;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

/** Load parent-owned secret approvals; raw values come only from host env. */
export function loadGondolinSecretBindings(
  agentDir: string,
  env: NodeJS.ProcessEnv = process.env,
): GondolinSecretBinding[] {
  const config = readConfig(agentDir);
  if (!config) return [];
  const bindings: GondolinSecretBinding[] = [];
  for (const [name, raw] of Object.entries(config)) {
    if (!ENV_NAME.test(name) || RESERVED_NAMES.has(name) || !raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error(`Gondolin secret binding ${name} is invalid.`);
    }
    const record = raw as Record<string, unknown>;
    if (Object.keys(record).some((key) => key !== "hosts") || !Array.isArray(record.hosts)) {
      throw new Error(`Gondolin secret binding ${name} is invalid.`);
    }
    const hosts = record.hosts
      .filter((host): host is string => typeof host === "string")
      .map((host) => host.trim())
      .filter(Boolean);
    if (hosts.length !== record.hosts.length || hosts.some((host) => host.includes("\u0000"))) {
      throw new Error(`Gondolin secret binding ${name} has invalid hosts.`);
    }
    const value = env[name];
    if (typeof value === "string" && value.length > 0) bindings.push({ name, value, hosts });
  }
  return bindings;
}
