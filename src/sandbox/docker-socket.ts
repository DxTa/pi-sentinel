import { realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";

const DOCKER_SOCKET_CANDIDATES = [
  "/var/run/docker.sock",
  "/run/docker.sock",
  join(homedir(), ".docker/run/docker.sock"),
  join(homedir(), ".orbstack/run/docker.sock"),
];

function parseUnixDockerHost(value: string | undefined): string | undefined {
  if (!value?.startsWith("unix://")) return undefined;
  const socketPath = value.slice("unix://".length);
  if (!socketPath.startsWith("/")) return undefined;
  try {
    return decodeURIComponent(socketPath);
  } catch {
    return undefined;
  }
}

function isKnownDockerSocketPath(value: string): boolean {
  const socketPath = resolve(value);
  if (basename(socketPath) !== "docker.sock") return false;
  const home = resolve(homedir());
  return [
    "/var/run",
    "/run",
    join(home, ".docker/run"),
    join(home, ".orbstack/run"),
  ].some((prefix) => socketPath === prefix + "/docker.sock");
}

export function resolveDockerSocketPaths(
  candidates: string[] = [parseUnixDockerHost(process.env.DOCKER_HOST), ...DOCKER_SOCKET_CANDIDATES].filter(
    (value): value is string => value !== undefined,
  ),
): string[] {
  const paths = new Set<string>();
  for (const candidate of candidates) {
    if (!isKnownDockerSocketPath(candidate)) continue;
    try {
      const canonical = realpathSync.native(candidate);
      if (!statSync(canonical).isSocket()) continue;
      paths.add(canonical);
      paths.add(resolve(candidate));
    } catch {
      // Missing or inaccessible socket; try next known location.
    }
  }
  return [...paths];
}
