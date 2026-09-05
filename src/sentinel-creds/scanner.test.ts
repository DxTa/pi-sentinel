import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { scanContentForSecrets, scanPathForSecrets } from "./scanner";

const tempPaths: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempPaths.push(dir);
  return dir;
}

async function makeFakeGitleaks(reportJson: string): Promise<string> {
  const dir = await makeTempDir("pi-gitleaks-bin-");
  const scriptPath = path.join(dir, "gitleaks");
  await writeFile(
    scriptPath,
    `#!/usr/bin/env bash
set -euo pipefail
report_path=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-path)
      report_path="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s' '${reportJson.replace(/'/g, "'\\''")}' > "$report_path"
`,
    "utf8",
  );
  await chmod(scriptPath, 0o755);
  return scriptPath;
}

afterEach(async () => {
  delete process.env.PI_GITLEAKS_BIN;
  await Promise.all(tempPaths.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("sentinel-creds scanner gitleaks integration", () => {
  it("prefers gitleaks clean result over heuristic false positive", async () => {
    process.env.PI_GITLEAKS_BIN = await makeFakeGitleaks("[]");

    const result = await scanContentForSecrets(
      'BUCKET_PATH="${BUCKET_PATH:-gs://ai-lab-training-model-repository/lora_repository}"\n',
    );

    expect(result.hasSecrets).toBe(false);
    expect(result.matches).toEqual([]);
  });

  it("keeps deterministic regex detections even when gitleaks returns clean", async () => {
    process.env.PI_GITLEAKS_BIN = await makeFakeGitleaks("[]");

    const result = await scanContentForSecrets("token='abcdefghijklmnop'\n");

    expect(result.hasSecrets).toBe(true);
    expect(result.matches[0]?.label).toBe("Generic Secret");
  });

  it("falls back to heuristic scanner when gitleaks is unavailable", async () => {
    process.env.PI_GITLEAKS_BIN = "/definitely/missing/gitleaks";

    const result = await scanContentForSecrets(
      'BUCKET_PATH="${BUCKET_PATH:-gs://ai-lab-training-model-repository/lora_repository}"\n',
    );

    expect(result.hasSecrets).toBe(true);
    expect(result.matches[0]?.label).toBe("High-Entropy Value");
  });

  it("keeps file-signature detections even when gitleaks returns clean", async () => {
    process.env.PI_GITLEAKS_BIN = await makeFakeGitleaks("[]");
    const dir = await makeTempDir("pi-gitleaks-file-");
    const filePath = path.join(dir, "secret.txt");
    await writeFile(filePath, "postgres://user:password123456@db.example.com/app\n", "utf8");

    const result = await scanPathForSecrets(filePath);

    expect(result).not.toBeNull();
    expect(result?.hasSecrets).toBe(true);
    expect(result?.matches[0]?.label).toBe("Database URL with password");
  });

  it("parses gitleaks findings into scan matches", async () => {
    process.env.PI_GITLEAKS_BIN = await makeFakeGitleaks(
      JSON.stringify([
        {
          RuleID: "generic-api-key",
          StartLine: 4,
          Match: "API_KEY=supersecretvalue",
          Secret: "supersecretvalue",
        },
      ]),
    );

    const result = await scanPathForSecrets("/tmp/example.txt");

    expect(result).not.toBeNull();
    expect(result?.hasSecrets).toBe(true);
    expect(result?.matches).toHaveLength(1);
    expect(result?.matches[0]).toMatchObject({
      label: "generic-api-key",
      line: 4,
      value: "supersecretvalue",
    });
    expect(result?.matches[0]?.snippet).toContain("****");
  });
});
