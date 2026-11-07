import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { rootCertificates } from "node:tls";

import { afterEach, describe, expect, it } from "vitest";
import { createSrtBackend, DEFAULT_SRT_HELPER_ENV } from "./backends/srt-backend.js";
import { buildSrtCommandSpec } from "./srt-command-spec.js";
import { buildSrtRuntimeConfig } from "./srt-runtime-config.js";
import { wrapCommandWithSandboxMacOS } from "@anthropic-ai/sandbox-runtime/dist/sandbox/macos-sandbox-utils.js";


const execFileAsync = promisify(execFile);
const runIntegration = process.env.PI_RUN_SRT_INTEGRATION === "1";
const maybeDescribe = runIntegration ? describe : describe.skip;
const tempPaths: string[] = [];

async function countProfileTempDirs(): Promise<number> {
  const entries = await readdir(tmpdir(), { withFileTypes: true });
  return entries.filter((entry) => entry.isDirectory() && entry.name.startsWith("pi-srt-profile-")).length;
}

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function runHelperInput(helperInput: object) {
  const repoRoot = process.cwd();
  const payloadDir = await makeTempDir("pi-srt-helper-input-");
  const payloadFile = path.join(payloadDir, "input.json");
  await writeFile(payloadFile, JSON.stringify(helperInput), { encoding: "utf8", mode: 0o600 });
  const env = { ...process.env, PI_SRT_HELPER_INPUT_FILE: payloadFile };
  delete env.PI_SRT_HELPER_INPUT_B64;

  try {
    const result = await execFileAsync(process.execPath, [path.join(repoRoot, "bin", "sandbox-run.mjs")], {
      cwd: repoRoot,
      env,
      timeout: 180_000,
    });
    if (existsSync(payloadFile)) throw new Error("SRT helper input file was not consumed");
    return result;
  } finally {
    await rm(payloadDir, { recursive: true, force: true });
  }
}

async function runHelper(command: string, label: string) {
  const cwd = await realpath(await makeTempDir("pi-srt-concurrent-" + label + "-"));
  const secretPath = path.join(cwd, ".env");
  await writeFile(secretPath, "SECRET_" + label + "=1\n", "utf8");
  await writeFile(path.join(cwd, "normal.txt"), "normal-" + label + "\n", "utf8");

  return runHelperInput({
    command: command + "; if [ -n \"$PI_SRT_HELPER_INPUT_FILE\" ] || [ -n \"$PI_SRT_HELPER_INPUT_B64\" ]; then printf 'HELPER_ENV_LEAK'; fi",
    cwd,
    runtimeConfig: {
      filesystem: {
        allowRead: [cwd, "/bin", "/usr", "/usr/bin", "/dev", "/etc/hosts", "/etc/resolv.conf", "/private/var/select"],
        allowWrite: [cwd],
        denyRead: ["/", secretPath],
        denyWrite: [secretPath],
      },
      network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
    },
    unmatchedHostAction: "deny",
    maskedShimPlan: {
      maskedFilePaths: [secretPath],
      maskedDenyPaths: [secretPath],
      shimCommands: ["cat", "head", "tail", "grep", "rg"],
    },
  });
}


maybeDescribe("sandbox-run SRT helper concurrency", () => {
  it("gives the child a read-only certificate copy while keeping the original private", async () => {
    const cwd = await realpath(await makeTempDir("pi-srt-ca-project-"));
    const caDir = await realpath(await makeTempDir("pi-srt-ca-source-"));
    const ca = path.join(caDir, "cert.pem");
    await writeFile(ca, rootCertificates[0]);
    const previous = process.env.SSL_CERT_FILE;
    process.env.SSL_CERT_FILE = ca;
    try {
      const result = await runHelperInput({
        command: `printf 'COPY:%s\n' "$SSL_CERT_FILE"; head -1 "$SSL_CERT_FILE"; if cat '${ca}' >/dev/null 2>&1; then echo ORIGINAL_READABLE; else echo ORIGINAL_DENIED; fi; if printf x >> "$SSL_CERT_FILE" 2>/dev/null; then echo COPY_WRITABLE; else echo COPY_READONLY; fi`,
        cwd,
        runtimeConfig: { filesystem: { allowRead: [cwd, "/bin", "/usr", "/dev", "/private/var/select"], allowWrite: [cwd], denyRead: ["/"], denyWrite: [] }, network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true } },
        unmatchedHostAction: "deny",
        trustedCa: { value: ca, path: ca },
        maskedShimPlan: { maskedFilePaths: [], maskedDenyPaths: [], shimCommands: [] },
      });
      const copy = /^COPY:(.+)$/m.exec(result.stdout)?.[1];
      expect(copy).toBeTruthy();
      expect(copy).not.toBe(ca);
      expect(result.stdout).toContain("-----BEGIN CERTIFICATE-----\nORIGINAL_DENIED\nCOPY_READONLY");
      expect(existsSync(copy!)).toBe(false);
    } finally {
      if (previous === undefined) delete process.env.SSL_CERT_FILE;
      else process.env.SSL_CERT_FILE = previous;
    }
  }, 30_000);

  it("allows read-only credential access while denying overwrite, removal, and rename", async () => {
    const cwd = await realpath(await makeTempDir("pi-srt-read-only-credential-"));
    const envPath = path.join(cwd, ".env");
    await writeFile(envPath, "TOKEN=synthetic-value\n", "utf8");
    const command = [
      "if printf 'TOKEN=changed\n' > .env 2>/dev/null; then echo WRITE_ALLOWED; else echo WRITE_DENIED; fi",
      "if rm .env 2>/dev/null; then echo REMOVE_ALLOWED; else echo REMOVE_DENIED; fi",
      "if mv .env .env.renamed 2>/dev/null; then echo RENAME_ALLOWED; else echo RENAME_DENIED; fi",
      "if [ \"$(cat .env)\" = 'TOKEN=synthetic-value' ]; then echo READ_ALLOWED; else echo READ_FAILED; fi",
    ].join("; ");
    const spec = buildSrtCommandSpec({
      command,
      cwd,
      repoRoot: cwd,
      sandboxConfig: {
        enabled: true,
        backend: "srt",
        profiles: {},
        defaultProfile: "offline-dev",
        roBinds: [],
        rwBinds: [],
      },
      profile: {
        name: "offline-dev",
        network: false,
        allowDocker: false,
        roBinds: [],
        rwBinds: [],
        env: { allow: [], deny: [] },
        maskedPaths: ["**/.env"],
      },
      unmaskedPaths: [{ path: envPath, writable: false }],
    });
    const runtimeConfig = buildSrtRuntimeConfig(spec);

    expect(runtimeConfig.filesystem.allowRead).toContain(envPath);
    expect(runtimeConfig.filesystem.allowWrite).not.toContain(envPath);
    expect(runtimeConfig.filesystem.denyWrite).toContain(envPath);

    const result = await runHelperInput({
      command,
      cwd,
      runtimeConfig,
      unmatchedHostAction: spec.networkPlan.unmatchedHostAction,
      maskedShimPlan: spec.maskedShimPlan,
      unmaskedPaths: spec.unmaskedPaths,
      envAllowPatterns: spec.envAllowPatterns,
      envDenyPatterns: spec.envDenyPatterns,
      execShimPlan: spec.execShimPlan,
    });
    expect(result.stdout).toBe("WRITE_DENIED\nREMOVE_DENIED\nRENAME_DENIED\nREAD_ALLOWED\n");
    expect(await readFile(envPath, "utf8")).toBe("TOKEN=synthetic-value\n");
  }, 180_000);

  it("keeps concurrent masked shim state isolated", async () => {
    const [a, b, c] = await Promise.all([
      runHelper("printf 'A:'; cat .env; printf 'N:'; cat normal.txt", "a"),
      runHelper("printf 'B:'; head .env; printf 'N:'; tail normal.txt", "b"),
      runHelper("printf 'C:'; grep masked .env; printf 'N:'; grep normal normal.txt", "c"),
    ]);

    expect(a.stdout).toBe("A:(masked)\nN:normal-a\n");
    expect(b.stdout).toBe("B:(masked)\nN:normal-b\n");
    expect(c.stdout).toBe("C:(masked)\nN:normal-c\n");
    expect(a.stderr + b.stderr + c.stderr).not.toContain("SECRET_");
  }, 180_000);


  it.skipIf(process.platform !== "darwin")("compacts high-cardinality sibling write-deny filters", async () => {
    const cwd = await makeTempDir("pi-srt-write-profile-shape-");
    const maskedDirectory = path.join(cwd, "masked.dir");
    const denyWrite = Array.from({ length: 6_000 }, (_, index) =>
      path.join(maskedDirectory, "protected-" + String(index).padStart(5, "0") + "-" + "x".repeat(72)),
    );
    const before = new Set(await readdir(tmpdir()));
    const macUtilsPath = "@anthropic-ai/sandbox-runtime/dist/sandbox/macos-sandbox-utils.js";
    const macUtils = await import(macUtilsPath) as unknown as {
      cleanupMacOSSandboxProfiles?: () => void;
    };

    try {
      wrapCommandWithSandboxMacOS({
        command: "true",
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [cwd], denyWithinAllow: denyWrite },
        allowUnixSockets: [],
        allowAllUnixSockets: false,
        allowLocalBinding: false,
        allowMachLookup: [],
        allowPty: false,
        allowGitConfig: false,
        unsetEnvVars: [],
        setEnvVars: {},
        maskedFileBinds: [],
        binShell: "bash",
      });

      const profileDirectory = (await readdir(tmpdir())).find((name) =>
        name.startsWith("pi-srt-profile-") && !before.has(name),
      );
      if (!profileDirectory) return; // Inline profiles stay below the spill threshold; semantic integration checks compilation.
      const profile = await readFile(path.join(tmpdir(), profileDirectory, "profile.sb"), "utf8");
      let inWriteDeny = false;
      let inMoveDeny = false;
      const filters: string[] = [];
      const moveFilters: string[] = [];
      for (const line of profile.split("\n")) {
        if (line.startsWith("(deny file-write*")) inWriteDeny = true;
        else if (inWriteDeny && line.startsWith("  (with message ")) inWriteDeny = false;
        else if (inWriteDeny && line.trim().startsWith("(")) filters.push(line.trim());

        if (line.startsWith("(deny file-write-unlink file-write-create")) inMoveDeny = true;
        else if (inMoveDeny && line.startsWith("  (with message ")) inMoveDeny = false;
        else if (inMoveDeny && line.trim().startsWith("(")) moveFilters.push(line.trim());
      }

      expect(filters.length).toBeLessThan(100);
      expect(moveFilters.length).toBeLessThan(100);
      expect(filters.some((filter) => filter.startsWith("(regex "))).toBe(true);
    } finally {
      macUtils.cleanupMacOSSandboxProfiles?.();
    }
  });

  it("keeps high-cardinality read/write denies and move pins exact", async () => {
    const cwd = await realpath(await makeTempDir("pi-srt-write-deny-compaction-"));
    const maskedDirectory = path.join(cwd, "masked.dir");
    const literalDirectory = path.join(cwd, "literal.dir");
    const allowedDirectory = path.join(cwd, "allowed");
    const protectedSuffix = "x".repeat(72);
    const firstProtectedLeaf = "protected-00000-" + protectedSuffix;
    const lastProtectedLeaf = "protected-05999-" + protectedSuffix;
    const outsideProtectedLeaf = "protected-06000-" + protectedSuffix;
    await mkdir(maskedDirectory);
    await mkdir(path.join(maskedDirectory, "masked.descendant"));
    await mkdir(path.join(maskedDirectory, lastProtectedLeaf));
    await writeFile(path.join(maskedDirectory, firstProtectedLeaf), "first");
    await writeFile(path.join(maskedDirectory, lastProtectedLeaf, "child"), "last");
    await writeFile(path.join(maskedDirectory, outsideProtectedLeaf), "outside");
    await mkdir(literalDirectory);
    await mkdir(path.join(literalDirectory, "secret{1}.name"));
    await mkdir(allowedDirectory);
    const readOnlyDirectory = path.join(cwd, "read-only.dir");
    await mkdir(readOnlyDirectory);
    const readOnlyProtectedPaths = Array.from({ length: 6 }, (_, index) =>
      path.join(readOnlyDirectory, "read-only-" + String(index).padStart(2, "0")),
    );

    const denyWrite = [
      path.join(maskedDirectory, "masked.name"),
      path.join(maskedDirectory, "masked.descendant"),
      path.join(maskedDirectory, "masked+move"),
      ...["secret.name", "secret+name", "secret{1}.name", "secret(name"].map((name) => path.join(literalDirectory, name)),
      ...Array.from({ length: 6_000 }, (_, index) =>
        path.join(maskedDirectory, "protected-" + String(index).padStart(5, "0") + "-" + protectedSuffix),
      ),
    ];
    const readDeny = [...denyWrite, ...readOnlyProtectedPaths];
    const helperInput = {
      command: [
        "if touch 'masked.dir/masked.name' 2>/dev/null; then echo EXACT_ALLOWED; else echo EXACT_DENIED; fi",
        "if touch 'masked.dir/masked.descendant/child' 2>/dev/null; then echo DESCENDANT_ALLOWED; else echo DESCENDANT_DENIED; fi",
        "if touch 'masked.dir/masked.name-neighbor' 2>/dev/null; then echo NEAR_PREFIX_ALLOWED; else echo NEAR_PREFIX_DENIED; fi",
        `if touch 'masked.dir/${firstProtectedLeaf}' 2>/dev/null; then echo HIGH_EXACT_ALLOWED; else echo HIGH_EXACT_DENIED; fi`,
        `if touch 'masked.dir/${lastProtectedLeaf}/child' 2>/dev/null; then echo HIGH_DESCENDANT_ALLOWED; else echo HIGH_DESCENDANT_DENIED; fi`,
        `if touch 'masked.dir/${outsideProtectedLeaf}' 2>/dev/null; then echo HIGH_NEAR_PREFIX_ALLOWED; else echo HIGH_NEAR_PREFIX_DENIED; fi`,
        `if cat 'masked.dir/${firstProtectedLeaf}' >/dev/null 2>&1; then echo HIGH_READ_EXACT_ALLOWED; else echo HIGH_READ_EXACT_DENIED; fi`,
        `if cat 'masked.dir/${lastProtectedLeaf}/child' >/dev/null 2>&1; then echo HIGH_READ_DESCENDANT_ALLOWED; else echo HIGH_READ_DESCENDANT_DENIED; fi`,
        `if cat 'masked.dir/${outsideProtectedLeaf}' >/dev/null 2>&1; then echo HIGH_READ_NEAR_PREFIX_ALLOWED; else echo HIGH_READ_NEAR_PREFIX_DENIED; fi`,
        "if mv 'masked.dir' 'allowed/moved-dir' 2>/dev/null; then echo MOVE_ALLOWED; else echo MOVE_PIN_DENIED; fi",
        "if mv 'read-only.dir' 'allowed/moved-read-only' 2>/dev/null; then echo READ_MOVE_ALLOWED; else echo READ_MOVE_PIN_DENIED; fi",
        "if touch 'literal.dir/secret.name' 2>/dev/null; then echo FACTORED_DOT_ALLOWED; else echo FACTORED_DOT_DENIED; fi",
        "if touch 'literal.dir/secret+name' 2>/dev/null; then echo FACTORED_PLUS_ALLOWED; else echo FACTORED_PLUS_DENIED; fi",
        "if touch 'literal.dir/secret{1}.name/child' 2>/dev/null; then echo FACTORED_DESCENDANT_ALLOWED; else echo FACTORED_DESCENDANT_DENIED; fi",
        "if touch 'literal.dir/secret(name' 2>/dev/null; then echo FACTORED_PAREN_ALLOWED; else echo FACTORED_PAREN_DENIED; fi",
        "if touch 'literal.dir/secret.name-neighbor' 2>/dev/null; then echo FACTORED_NEAR_PREFIX_ALLOWED; else echo FACTORED_NEAR_PREFIX_DENIED; fi",
      ].join("; "),
      cwd,
      runtimeConfig: {
        filesystem: {
          allowRead: [cwd, "/bin", "/usr", "/usr/bin", "/dev", "/etc/hosts", "/etc/resolv.conf", "/private/var/select"],
          allowWrite: [cwd],
          denyRead: readDeny,
          denyWrite,
        },
        network: { allowedDomains: [], deniedDomains: [], strictAllowlist: true },
      },
      unmatchedHostAction: "deny",
      maskedShimPlan: { maskedFilePaths: [], maskedDenyPaths: [], shimCommands: [] },
    };
    expect(Buffer.byteLength(JSON.stringify(helperInput), "utf8")).toBeGreaterThan(65_536);

    const profileDirsBefore = await countProfileTempDirs();
    let stdout = "";
    try {
      stdout = (await runHelperInput(helperInput)).stdout;
    } catch (error) {
      const stderr = String((error as NodeJS.ErrnoException & { stderr?: Buffer | string }).stderr ?? "");
      const cause = /data object length \d+ exceeds maximum/i.test(stderr) ? "sbpl-object-limit"
        : /E2BIG/i.test(stderr) ? "spawn-e2big"
        : /operation not permitted|not permitted|denied/i.test(stderr) ? "sandbox-denied"
        : /sandbox|profile/i.test(stderr) ? "sandbox-or-profile"
        : "other";
      const errorCode = (error as NodeJS.ErrnoException).code;
      const safeCode = typeof errorCode === "string" && /^[A-Z][A-Z0-9_]*$/.test(errorCode)
        ? errorCode
        : typeof errorCode === "number" ? "exit-" + errorCode : "unknown";
      const tags = [
        /data object length/i.test(stderr) ? "object-limit" : "",
        /error reading string/i.test(stderr) ? "sbpl-string-limit" : "",
        /regular expression|regex/i.test(stderr) ? "regex" : "",
        /syntax|parse|invalid/i.test(stderr) ? "parse" : "",
        /sandbox_init|sandbox init/i.test(stderr) ? "sandbox-init" : "",
        /operation not permitted|not permitted|denied/i.test(stderr) ? "permission-denied" : "",
        /profile not found|cannot find.{0,20}profile|could not find.{0,20}profile/i.test(stderr) ? "profile-not-found" : "",
        /profile/i.test(stderr) ? "profile" : "",
        /TypeError|ReferenceError|RangeError|SyntaxError/i.test(stderr) ? "runtime-exception" : "",
        /realpath|normalize|resolve/i.test(stderr) ? "path-resolution" : "",
        /ENOENT|no such file|not found/i.test(stderr) ? "missing-file" : "",
        /config|unsupported|validation/i.test(stderr) ? "configuration" : "",
        /filter|regex|rule/i.test(stderr) ? "filter-generation" : "",
        /sandbox-run error:/i.test(stderr) ? "helper-error" : "",
        /Error:/i.test(stderr) ? "exception" : "",
      ].filter(Boolean).join(",") || "none";
      stdout = "SRT_FAILURE:" + cause + ":code-" + safeCode + ":stderr-bytes-" + Buffer.byteLength(stderr, "utf8") + ":tags-" + tags;
    }

    expect(await countProfileTempDirs()).toBe(profileDirsBefore);
    expect(stdout).toBe("EXACT_DENIED\nDESCENDANT_DENIED\nNEAR_PREFIX_ALLOWED\nHIGH_EXACT_DENIED\nHIGH_DESCENDANT_DENIED\nHIGH_NEAR_PREFIX_ALLOWED\nHIGH_READ_EXACT_DENIED\nHIGH_READ_DESCENDANT_DENIED\nHIGH_READ_NEAR_PREFIX_ALLOWED\nMOVE_PIN_DENIED\nREAD_MOVE_PIN_DENIED\nFACTORED_DOT_DENIED\nFACTORED_PLUS_DENIED\nFACTORED_DESCENDANT_DENIED\nFACTORED_PAREN_DENIED\nFACTORED_NEAR_PREFIX_ALLOWED\n");
  }, 180_000);

  it("runs oversized wrapped command through private helper-file transport", async () => {
    const cwd = await makeTempDir("pi-srt-oversized-command-");
    const command = `#${"x".repeat(100_000)}\nprintf 'OVERSIZED_COMMAND_OK\n'`;
    const wrapped = await createSrtBackend().wrapCommand({
      command,
      cwd,
      repoRoot: process.cwd(),
      sandboxConfig: {
        enabled: true,
        profiles: {},
        defaultProfile: "offline-dev",
        roBinds: [],
        rwBinds: [],
      },
      preResolvedProfile: {
        name: "offline-dev",
        network: false,
        allowDocker: false,
        roBinds: [],
        rwBinds: [],
        env: { allow: [], deny: [] },
        maskedPaths: [],
      },
    });

    if (!wrapped || "block" in wrapped) throw new Error("SRT command wrapping unavailable");
    expect(wrapped.helperPayloadBytes).toBeGreaterThan(65_536);
    expect(wrapped.rawCommandBytes).toBe(Buffer.byteLength(command, "utf8"));
    expect(wrapped.command.length).toBeLessThan(2_000);
    expect(wrapped.command).toContain(`${DEFAULT_SRT_HELPER_ENV}=''`);
    expect(wrapped.command).toContain("PI_SRT_HELPER_INPUT_FILE=");

    const profileDirsBefore = await countProfileTempDirs();
    let stdout: string | undefined;
    try {
      const result = await execFileAsync("bash", ["-lc", wrapped.command], { cwd, timeout: 120_000 });
      stdout = result.stdout.toString();
    } catch (error) {
      // Emit fixed failure labels only; never expose command or temp paths.
      const stderr = String((error as NodeJS.ErrnoException & { stderr?: Buffer | string }).stderr ?? "");
      const objectLimit = /data object length (\d+) exceeds maximum \((\d+)\)/i.exec(stderr);
      const safeCause = objectLimit
        ? "sbpl-object-limit-actual-" + objectLimit[1] + "-max-" + objectLimit[2]
        : ["spawn E2BIG", "Maximum call stack size exceeded"]
          .find((cause) => stderr.includes(cause))
        ?? (/operation not permitted|not permitted/i.test(stderr) ? "sandbox-denied" : undefined)
        ?? (/sandbox_init/i.test(stderr) ? "sandbox-init" : undefined)
        ?? (/profile.{0,80}(invalid|error|syntax|parse|load|read)|(?:invalid|error|syntax|parse|load|read).{0,80}profile/i.test(stderr) ? "profile-rejected" : undefined)
        ?? (/(too many|resource|memory|limit)/i.test(stderr) ? "resource-limit" : undefined);
      const errorCode = (error as NodeJS.ErrnoException).code;
      const safeCode = typeof errorCode === "string" && /^[A-Z][A-Z0-9_]*$/.test(errorCode)
        ? errorCode
        : typeof errorCode === "number" ? "exit-" + errorCode : "unclassified";
      const stderrTags = [
        [/sandbox/i, "sandbox"],
        [/profile/i, "profile"],
        [/permission|denied|not permitted/i, "permission"],
        [/parse|syntax|invalid|compile/i, "parse"],
        [/no such file|not found/i, "missing"],
        [/E2BIG/i, "e2big"],
      ].filter(([pattern]) => pattern.test(stderr)).map(([, tag]) => tag).join("-") || "none";
      stdout = "SRT_FAILURE:" + (safeCause ?? safeCode) + ":stderr-bytes-" + Buffer.byteLength(stderr, "utf8") + ":tags-" + stderrTags;
    } finally {
      wrapped.cleanup?.();
    }
    expect(await countProfileTempDirs()).toBe(profileDirsBefore);
    expect(stdout, "SRT helper execution failed").toBe("OVERSIZED_COMMAND_OK\n");
  }, 240_000);

});
