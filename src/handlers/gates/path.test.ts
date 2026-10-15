import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, sep } from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

import { describePathGate } from "./path";
import { getPathPolicyCandidates, hasProtectedEnvSelector } from "#src/path-utils";
import type { ToolCallContext } from "./types";

function context(toolName: string, filePath: string, cwd: string): ToolCallContext {
  return {
    toolName,
    input: { path: filePath },
    agentName: null,
    toolCallId: "tool-1",
    cwd,
  };
}

function pathDeny() {
  return {
    toolName: "path",
    state: "deny" as const,
    matchedPattern: "*.env",
    source: "tool" as const,
    origin: "builtin" as const,
  };
}

function checkPath(toolName: string, filePath: string, cwd: string) {
  return describePathGate(
    context(toolName, filePath, cwd),
    () => pathDeny(),
    () => [],
  );
}

describe("describePathGate dotenv reads", () => {
  it("resolves relative policy candidates against the supplied workspace", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const processCwdFile = realpathSync.native(join(process.cwd(), "src/path-utils.ts"));

    try {
      expect(getPathPolicyCandidates("src/path-utils.ts", workspace)).not.toContain(processCwdFile);
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("allows a workspace-local dotenv read past the path denial", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const envPath = join(workspace, ".env");
    writeFileSync(envPath, "TOKEN=secret-value\n");

    try {
      expect(checkPath("read", envPath, workspace)).toBeNull();
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("overrides explicit project dotenv denies for masked workspace reads", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const envPath = join(workspace, ".env");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    const projectDeny = (_surface: string, input: unknown) => {
      return basename((input as { path: string }).path).toLowerCase() === ".env"
        ? { ...pathDeny(), origin: "project" as const }
        : { ...pathDeny(), state: "allow" as const, matchedPattern: "*" };
    };

    try {
      expect(describePathGate(
        context("read", envPath, workspace),
        projectDeny,
        () => [],
      )).toBeNull();
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("keeps explicit dotenv asks behind approval", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const envPath = join(workspace, ".env");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    const projectAsk = (_surface: string, input: unknown) =>
      basename((input as { path: string }).path).toLowerCase() === ".env"
        ? { ...pathDeny(), state: "ask" as const, origin: "project" as const }
        : { ...pathDeny(), state: "allow" as const, matchedPattern: "*" };

    try {
      expect(describePathGate(
        context("read", envPath, workspace),
        projectAsk,
        () => [],
      )).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("blocks file-URL dotenv writes and external dotenv reads", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const outside = mkdtempSync(join(tmpdir(), "pi-env-outside-"));
    const envPath = join(workspace, ".env");
    const outsideEnvPath = join(outside, ".env");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    writeFileSync(outsideEnvPath, "TOKEN=secret-value\n");
    const encodedEnvUrl = pathToFileURL(envPath).href.replace(".env", "%2Eenv");
    const outsideEnvUrl = pathToFileURL(outsideEnvPath).href;
    const dotenvPolicy = (_surface: string, input: unknown) =>
      basename((input as { path: string }).path).toLowerCase() === ".env"
        ? pathDeny()
        : { ...pathDeny(), state: "allow" as const, matchedPattern: "*" };

    try {
      expect(describePathGate(
        context("write", encodedEnvUrl, workspace),
        dotenvPolicy,
        () => [],
      )).toMatchObject({ surface: "path" });
      expect(describePathGate(
        context("read", outsideEnvUrl, workspace),
        dotenvPolicy,
        () => [],
      )).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("checks normalized and case-folded paths against the strictest policy", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const envPath = join(workspace, ".env");
    const uppercaseExtensionPath = join(workspace, "production.ENV");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    writeFileSync(uppercaseExtensionPath, "TOKEN=secret-value\n");
    const policy = (_surface: string, input: unknown) => {
      const fileName = basename((input as { path: string }).path);
      return fileName === ".env" || fileName === "production.env"
        ? pathDeny()
        : { ...pathDeny(), state: "allow" as const, matchedPattern: "*" };
    };

    try {
      for (const filePath of [`${envPath}${sep}.`, uppercaseExtensionPath]) {
        expect(describePathGate(
          context("write", filePath, workspace),
          policy,
          () => [],
        ), filePath).toMatchObject({ surface: "path" });
      }
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("preserves directory-scoped denies for case-variant dotenv paths", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const uppercaseDirectory = join(workspace, "CONFIG");
    const envPath = join(uppercaseDirectory, ".env");
    mkdirSync(uppercaseDirectory);
    writeFileSync(envPath, "TOKEN=secret-value\n");
    const policy = (_surface: string, input: unknown) => {
      const requestedPath = (input as { path: string }).path.replaceAll("\\", "/");
      if (requestedPath.endsWith("/config/.env")) {
        return { ...pathDeny(), matchedPattern: "config/.env" };
      }
      return basename(requestedPath).toLowerCase() === ".env"
        ? pathDeny()
        : { ...pathDeny(), state: "allow" as const, matchedPattern: "*" };
    };

    try {
      expect(describePathGate(
        context("read", envPath, workspace),
        policy,
        () => [],
      )).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("does not let an env-named symlink bypass a deny on its real target", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const secrets = join(workspace, "secrets");
    mkdirSync(secrets);
    const deployKey = join(secrets, "deploy_key");
    const envAlias = join(workspace, ".env.local");
    writeFileSync(deployKey, "private-key-material\n");
    symlinkSync(deployKey, envAlias);
    const policy = (_surface: string, input: unknown) => {
      const requestedPath = (input as { path: string }).path;
      const fileName = basename(requestedPath).toLowerCase();
      if (requestedPath.includes("secrets") && fileName === "deploy_key") {
        return { ...pathDeny(), matchedPattern: "secrets-policy" };
      }
      if (fileName === ".env.local") {
        return { ...pathDeny(), matchedPattern: "*.env.*" };
      }
      return { ...pathDeny(), state: "allow" as const, matchedPattern: "*" };
    };

    try {
      expect(describePathGate(
        context("read", envAlias, workspace),
        policy,
        () => [],
      )).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("keeps case-variant and symlink dotenv writes behind the deny rule", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const outside = mkdtempSync(join(tmpdir(), "pi-env-outside-"));
    const uppercasePath = join(workspace, ".ENV");
    const aliasPath = join(workspace, "local-config");
    const externalUppercasePath = join(outside, ".ENV");
    const checkedPaths: string[] = [];
    writeFileSync(uppercasePath, "TOKEN=secret-value\n");
    writeFileSync(externalUppercasePath, "TOKEN=secret-value\n");
    symlinkSync(uppercasePath, aliasPath);
    const caseSensitivePolicy = (_surface: string, input: unknown) => {
      const requestedPath = (input as { path: string }).path;
      checkedPaths.push(requestedPath);
      return requestedPath.replaceAll("\\", "/").endsWith("/.env")
        ? pathDeny()
        : { ...pathDeny(), state: "allow" as const, matchedPattern: "*" };
    };

    try {
      for (const filePath of [uppercasePath, aliasPath]) {
        const gate = describePathGate(
          context("write", filePath, workspace),
          caseSensitivePolicy,
          () => [],
        );
        expect(checkedPaths).toContain(filePath);
        expect(checkedPaths.some((checkedPath) =>
          checkedPath.replaceAll("\\", "/").toLowerCase().endsWith("/.env"),
        )).toBe(true);
        expect(gate, filePath).toMatchObject({ surface: "path" });
      }
      expect(describePathGate(
        context("read", externalUppercasePath, workspace),
        caseSensitivePolicy,
        () => [],
      )).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("keeps case-variant and encoded dotenv selectors protected", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-selector-"));
    const encodedPath = pathToFileURL(join(workspace, ".ENV")).href.replace(".ENV", "%2EENV");

    try {
      expect(hasProtectedEnvSelector("grep", { path: workspace, glob: "*.ENV" })).toBe(true);
      expect(hasProtectedEnvSelector("find", { path: encodedPath })).toBe(true);
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("keeps writes, edits, example files, and external dotenv reads protected", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-env-path-"));
    const outside = mkdtempSync(join(tmpdir(), "pi-env-outside-"));
    const envPath = join(workspace, ".env");
    const examplePath = join(workspace, ".env.example");
    const outsidePath = join(outside, ".env");
    writeFileSync(envPath, "TOKEN=secret-value\n");
    writeFileSync(examplePath, "TOKEN=placeholder\n");
    writeFileSync(outsidePath, "TOKEN=secret-value\n");

    try {
      for (const toolName of ["write", "edit"] as const) {
        expect(checkPath(toolName, envPath, workspace)).toMatchObject({ surface: "path" });
      }
      expect(checkPath("read", examplePath, workspace)).toMatchObject({ surface: "path" });
      expect(checkPath("read", outsidePath, workspace)).toMatchObject({ surface: "path" });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });
});
