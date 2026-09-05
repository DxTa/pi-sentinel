import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const runIntegration = process.env.PI_RUN_SRT_INTEGRATION === "1";
const maybeDescribe = runIntegration ? describe : describe.skip;
const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function encodeHelperInput(input: unknown): string {
  return Buffer.from(JSON.stringify(input), "utf8").toString("base64");
}

async function runHelper(command: string, label: string) {
  const repoRoot = process.cwd();
  const cwd = await makeTempDir(`pi-srt-concurrent-${label}-`);
  const secretPath = path.join(cwd, ".env");
  await writeFile(secretPath, `SECRET_${label}=1\n`, "utf8");
  await writeFile(path.join(cwd, "normal.txt"), `normal-${label}\n`, "utf8");

  const helperInput = {
    command,
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
  };

  return await execFileAsync(process.execPath, [path.join(repoRoot, "bin", "sandbox-run.mjs")], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PI_SRT_HELPER_INPUT_B64: encodeHelperInput(helperInput),
    },
    timeout: 120_000,
  });
}

maybeDescribe("sandbox-run SRT helper concurrency", () => {
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
});
