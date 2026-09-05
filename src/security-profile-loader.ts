import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

import { isPermissionState, toRecord } from "./common";
import type { FlatPermissionConfig } from "./types";

const SECURITY_PROFILE_ENV = "PI_SECURITY_SCAN_PROFILE";
const SECURITY_PROFILE_FILENAME = "security-scan.json";
const ALLOWED_SECURITY_PROFILES = new Set([
  "scan-discovery",
  "scan-verification",
  "scan-remediation",
]);

const FAIL_CLOSED_PERMISSION: FlatPermissionConfig = {
  write: "deny",
  edit: "deny",
  process: "deny",
  bash: { "*": "deny" },
};

function getRequestedSecurityProfileName(
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const value = env[SECURITY_PROFILE_ENV]?.trim();
  return value || null;
}

export function getActiveSecurityProfileName(
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const value = getRequestedSecurityProfileName(env);
  if (!value) {
    return null;
  }
  return ALLOWED_SECURITY_PROFILES.has(value) ? value : null;
}

export function getSecurityProfilesPath(bundledConfigPath: string): string {
  return join(dirname(bundledConfigPath), "profiles", SECURITY_PROFILE_FILENAME);
}

export function getSecurityProfileStamp(bundledConfigPath: string): string {
  const profileName = getActiveSecurityProfileName();
  if (!profileName) {
    return "security-profile:none";
  }
  const profilePath = getSecurityProfilesPath(bundledConfigPath);
  try {
    return `security-profile:${profileName}:${statSync(profilePath).mtimeMs}`;
  } catch {
    return `security-profile:${profileName}:missing`;
  }
}

function normalizeFlatPermissionValue(
  value: unknown,
): FlatPermissionConfig | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }

  const normalized: FlatPermissionConfig = {};
  let hasAny = false;
  for (const [surface, rawAction] of Object.entries(toRecord(value))) {
    if (isPermissionState(rawAction)) {
      normalized[surface] = rawAction;
      hasAny = true;
      continue;
    }

    if (!rawAction || typeof rawAction !== "object" || Array.isArray(rawAction)) {
      continue;
    }

    const actionMap: Record<string, "allow" | "deny" | "ask"> = {};
    let mapHasAny = false;
    for (const [pattern, action] of Object.entries(toRecord(rawAction))) {
      if (isPermissionState(action)) {
        actionMap[pattern] = action;
        mapHasAny = true;
      }
    }
    if (mapHasAny) {
      normalized[surface] = actionMap;
      hasAny = true;
    }
  }

  return hasAny ? normalized : undefined;
}

export function loadActiveSecurityProfilePermission(
  bundledConfigPath: string,
): { permission?: FlatPermissionConfig; issues: string[]; profileName: string | null } {
  const requestedProfileName = getRequestedSecurityProfileName();
  if (!requestedProfileName) {
    return { issues: [], profileName: null };
  }

  const profileName = getActiveSecurityProfileName();
  if (!profileName) {
    return {
      permission: FAIL_CLOSED_PERMISSION,
      issues: [`Unknown security scan profile '${requestedProfileName}' requested via ${SECURITY_PROFILE_ENV}; applying fail-closed deny profile`],
      profileName: requestedProfileName,
    };
  }

  const profilePath = getSecurityProfilesPath(bundledConfigPath);
  if (!existsSync(profilePath)) {
    return {
      permission: FAIL_CLOSED_PERMISSION,
      issues: [`Security scan profile file missing: ${profilePath}; applying fail-closed deny profile`],
      profileName,
    };
  }

  try {
    const parsed = JSON.parse(readFileSync(profilePath, "utf-8")) as unknown;
    const profile = toRecord(parsed)[profileName];
    const permission = normalizeFlatPermissionValue(profile);
    if (!permission) {
      return {
        permission: FAIL_CLOSED_PERMISSION,
        issues: [`Security scan profile '${profileName}' is missing or invalid in ${profilePath}; applying fail-closed deny profile`],
        profileName,
      };
    }
    return { permission, issues: [], profileName };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      permission: FAIL_CLOSED_PERMISSION,
      issues: [`Failed to load security scan profile '${profileName}' from ${profilePath}: ${message}; applying fail-closed deny profile`],
      profileName,
    };
  }
}
