import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { rootCertificates } from "node:tls";
import { X509Certificate } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("sandbox-run helper input files", () => {
  it("copies only valid certificates from a CA bundle", async () => {
    const helperPath = pathToFileURL(path.join(process.cwd(), "bin", "sandbox-run-env.mjs")).href;
    const { certificateOnlyBundle } = await import(helperPath) as {
      certificateOnlyBundle: (text: string) => string | null;
    };
    expect(certificateOnlyBundle(`# comment\n${rootCertificates[0]}\n`)).toBe(new X509Certificate(rootCertificates[0]).toString());
    expect(certificateOnlyBundle(`${rootCertificates[0]}\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----`)).toBeNull();
    expect(certificateOnlyBundle("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")).toBeNull();
    expect(certificateOnlyBundle("# no certificates")).toBeNull();
    expect(certificateOnlyBundle(`${rootCertificates[0]}\n-----BEGIN TRUSTED CERTIFICATE-----\nabc\n-----END TRUSTED CERTIFICATE-----`)).toBeNull();
  });

  it("rejects symlink CA files", async () => {
    const helperPath = pathToFileURL(path.join(process.cwd(), "bin", "sandbox-run-env.mjs")).href;
    const { readTrustedCaBundle } = await import(helperPath) as {
      readTrustedCaBundle: (file: string) => Promise<string | null>;
    };
    const dir = await makeTempDir("pi-ca-test-");
    await writeFile(path.join(dir, "ca.pem"), rootCertificates[0]);
    await symlink(path.join(dir, "ca.pem"), path.join(dir, "link.pem"));
    expect(await readTrustedCaBundle(path.join(dir, "ca.pem"))).toBe(new X509Certificate(rootCertificates[0]).toString());
    expect(await readTrustedCaBundle(path.join(dir, "link.pem"))).toBeNull();
  });

  it("pins Docker socket selection over an inherited context", async () => {
    const helperPath = pathToFileURL(path.join(process.cwd(), "bin", "sandbox-run-env.mjs")).href;
    const { setDockerHostEnvironment } = await import(helperPath) as {
      setDockerHostEnvironment: (env: Record<string, string | undefined>, dockerHost: string) => void;
    };
    const env = { DOCKER_CONTEXT: "remote", DOCKER_HOST: "tcp://attacker.invalid", PATH: "/bin" };

    setDockerHostEnvironment(env, "unix:///tmp/docker.sock");

    expect(env).toEqual({ DOCKER_HOST: "unix:///tmp/docker.sock", PATH: "/bin" });
  });

  it("consumes private file input before sandbox setup", async () => {
    const dir = await makeTempDir("pi-srt-helper-test-");
    const file = path.join(dir, "input.json");
    await writeFile(file, "null", { encoding: "utf8", mode: 0o600 });

    await expect(execFileAsync(process.execPath, [path.join(process.cwd(), "bin", "sandbox-run.mjs")], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        PI_SRT_HELPER_INPUT_FILE: file,
        PI_SRT_HELPER_INPUT_B64: Buffer.from("null").toString("base64"),
      },
      timeout: 15_000,
    })).rejects.toMatchObject({ code: 1 });

    expect(existsSync(file)).toBe(false);
  });

  it("rejects and preserves files outside its private temp directory", async () => {
    const dir = await makeTempDir("pi-srt-untrusted-");
    const file = path.join(dir, "input.json");
    await writeFile(file, "null", { encoding: "utf8", mode: 0o600 });

    const result = execFileAsync(process.execPath, [path.join(process.cwd(), "bin", "sandbox-run.mjs")], {
      cwd: process.cwd(),
      env: { ...process.env, PI_SRT_HELPER_INPUT_FILE: file },
      timeout: 15_000,
    });
    await expect(result).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("must name a private helper input file"),
    });
    expect(existsSync(file)).toBe(true);
  });
});
