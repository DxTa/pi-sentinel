import { existsSync } from "node:fs";
import { basename, delimiter, join } from "node:path";

const NODE_EXECUTABLE = /^node(?:\.exe)?$/i;
const SCRIPT_RUNTIME = /^(?:node|bun)(?:\.exe)?$/i;

function executableName(path: string): string {
  return basename(path.replaceAll("\\", "/"));
}

function nodeFromPath(pathEnv: string): string {
  return pathEnv.split(delimiter).map((dir) => join(dir, "node")).find((candidate) => existsSync(candidate)) ?? "node";
}

/**
 * Runtime for a plain helper script. A compiled host (for example pi-bolt) has a
 * `process.execPath` that treats script arguments as its own CLI, so use `node` from PATH.
 */
export function helperRuntimePath(execPath = process.execPath, pathEnv = process.env.PATH ?? ""): string {
  return SCRIPT_RUNTIME.test(executableName(execPath)) ? execPath : nodeFromPath(pathEnv);
}

/**
 * Node.js itself, for code that needs Node flags (`--experimental-strip-types`) or
 * Node native addons (onnxruntime-node). Bun and compiled hosts resolve to `node` from PATH.
 */
export function nodeRuntimePath(execPath = process.execPath, pathEnv = process.env.PATH ?? ""): string {
  return NODE_EXECUTABLE.test(executableName(execPath)) ? execPath : nodeFromPath(pathEnv);
}
