import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { maskDotenvReadResult, maskDotenvText, maskSecretValues, parseDotenvValues, readDotenvSourceWithinLimit } from "./env-mask.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("maskDotenvText", () => {
  it("masks comments and preserves only unambiguous variable names", () => {
    const input = [
      "# keep this comment",
      "# documented API_KEY=example",
      "API_KEY=plain-secret",
      "service.token=dotted-secret",
      "API-KEY=hyphen-secret",
      "1KEY=digit-leading",
      "@KEY=at-leading",
      "ApiKey=mixed-case-secret",
      "service name=space-name",
      "export DB_PASSWORD='quoted-secret' # note",
      "EMPTY=",
      "",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "# ****",
      "# ****",
      "API_KEY=****",
      "service.token=****",
      "API-KEY=****",
      "****",
      "****",
      "****",
      "****",
      "export DB_PASSWORD=****",
      "****",
      "",
    ].join("\n"));
  });

  it("hides base64-shaped keys and empty or malformed values", () => {
    const input = [
      "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
      "API_KEY=",
      "API_KEY==secret-value",
      "ApiKey=secret-value",
      "API_KEY=secret-value",
      "",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "****",
      "****",
      "****",
      "****",
      "API_KEY=****",
      "",
    ].join("\n"));
  });

  it("masks every nonblank comment, including PEM and token text", () => {
    const input = [
      "# local development settings",
      '#   "private_key": "-----BEGIN PRIVATE KEY-----',
      "# MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAB+abc/def",
      "# old prod token: sk_live_1234567890",
      "TOKEN=plain-secret",
      "",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "# ****",
      "# ****",
      "# ****",
      "# ****",
      "TOKEN=****",
      "",
    ].join("\n"));
  });

  it("masks continuation lines of commented-out quoted secrets", () => {
    const input = [
      "# keep this comment",
      '# PRIVATE_KEY="first-commented-line',
      "# MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAB+abc/def",
      '# closing-comment-line"',
      "# keep this later comment",
      "MODE=dev",
      "",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "# ****",
      "# ****",
      "# ****",
      "# ****",
      "# ****",
      "MODE=****",
      "",
    ].join("\n"));
  });

  it("redacts dotenv-like lines that are not safe assignments", () => {
    const input = [
      'GCP_SA="{',
      '  \"type\": \"service_account\",',
      '  \"private_key\": \"-----BEGIN PRIVATE KEY-----',
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAB+abc/def=",
      '-----END PRIVATE KEY-----\"',
      '}",',
      "malformed: credential-secret",
      "BROKEN KEY=private-key-secret",
      "",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "GCP_SA=****",
      "****",
      "****",
      "****",
      "****",
      "****",
      "****",
      "****",
      "",
    ].join("\n"));
  });

  it("hides every line of a multiline quoted value", () => {
    const input = 'MULTILINE="first line\nsecond line"\nBACKTICK=`first backtick\nsecond backtick`\nAFTER=value\n';

    expect(maskDotenvText(input)).toBe("MULTILINE=****\n****\nBACKTICK=****\n****\nAFTER=****\n");
  });

  it("masks CR-prefixed comment assignments without merging later assignments", () => {
    const input = '\r# NOTE="ignored\nTOKEN=older-secret\nTOKEN=newer-secret\n# closing "\n';

    expect(maskDotenvText(input)).toBe(
      '\r# ****\nTOKEN=****\nTOKEN=****\n# ****\n',
    );
  });

  it("masks assignment values containing line separator characters", () => {
    const input = [
      "TOKEN=unicode-secret\u2028tail",
      "PARAGRAPH=paragraph-secret\u2029tail",
      "CR_VALUE=carriage-secret\rtail",
      "",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "TOKEN=****",
      "PARAGRAPH=****",
      "CR_VALUE=****",
      "",
    ].join("\n"));
  });

  it("masks multiline values whose quote follows whitespace and a newline", () => {
    const input = ["TOKEN= ", '"first-secret', 'second-secret"', ""].join("\n");

    expect(maskDotenvText(input)).toBe([
      "TOKEN=****",
      "****",
      "****",
      "",
    ].join("\n"));
  });

  it("fails closed after an unterminated quote", () => {
    const input = [
      'BROKEN="unterminated',
      "TOKEN=older-secret",
      "TOKEN=newer-secret",
      "# note=comment-after",
      "",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "BROKEN=****",
      "****",
      "****",
      "****",
      "",
    ].join("\n"));
  });

  it("fails closed when a quoted value ends in an escaped quote", () => {
    const input = [
      'DIR="C:\\secrets\\"',
      "TOKEN=older-secret",
      "TOKEN=newer-secret",
    ].join("\n");

    expect(maskDotenvText(input)).toBe([
      "DIR=****",
      "****",
      "****",
    ].join("\n"));
  });
});

describe("maskDotenvReadResult", () => {
  it("fails closed when output lines do not match the full file", () => {
    const source = 'TOKEN="first-part\nsecret-middle\nlast-part"';

    expect(maskDotenvReadResult("unexpected-secret", source, 1, 1)).toBe("****");
  });

  it("fails closed when result has unverified lines after the mapped range", () => {
    const source = "TOKEN=secret-value\nprivate-key-body";

    expect(maskDotenvReadResult(source, source, 0, 1)).toBe("****");
  });


});

describe("maskSecretValues", () => {
  it("masks exact long values literally, longest first, and skips short values", () => {
    const input = "value=long-secret-token; another=p@ss.w[rd]; tier=dev";

    expect(maskSecretValues(input, ["long-secret", "long-secret-token", "p@ss.w[rd]", "dev"]))
      .toBe("value=****; another=****; tier=dev");

    expect(maskSecretValues("boundary=abcde; next=abcdef", ["abcde", "abcdef"]))
      .toBe("boundary=abcde; next=****");
  });
});

describe("parseDotenvValues", () => {
  it("reads plain, exported, quoted, multiline, and short assignment values", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "pi-env-mask-"));
    temporaryDirectories.push(directory);
    const envPath = path.join(directory, ".env");
    await writeFile(envPath, [
      "PLAIN=older-plain-secret",
      "PLAIN=plain-secret-token",
      'DIR="C:\\secrets\\"',
      "service.token=dotted-secret-token",
      "API-KEY=hyphen-secret-token",
      "1KEY=digit-leading-secret",
      "@KEY=at-leading-secret",
      "service name=space-key-secret",
      '\r# NOTE="ignored',
      "TOKEN_CR=older-secret",
      "TOKEN_CR=newer-secret",
      '# closing "',
      "export EXPORTED=exported-secret",
      "QUOTED='quoted-secret'",
      "UNICODE=unicode-secret\u2028tail",
      "PARAGRAPH=paragraph-secret\u2029tail",
      "CARRIAGE=carriage-secret\rtail",
      "SPACED= ",
      '"first spaced-secret',
      'second spaced-secret"',
      'MULTILINE="first line',
      'second line"',
      'BACKTICK=`first backtick',
      'second backtick`',
      "SHORT=dev",
      'BROKEN="unterminated',
      "TOKEN=older-secret",
      "TOKEN=newer-secret",
      "# note=comment-after",
      "# COMMENT=ignored-secret",
      "",
    ].join("\n"), "utf8");

    const values = await parseDotenvValues(envPath);
    expect(values.sort()).toEqual([
      "older-plain-secret",
      "plain-secret-token",
      'C:\\secrets\\',
      "dotted-secret-token",
      "hyphen-secret-token",
      "digit-leading-secret",
      "at-leading-secret",
      "space-key-secret",
      '"unterminated',
      "older-secret",
      "newer-secret",
      "older-secret",
      "newer-secret",
      "exported-secret",
      "quoted-secret",
      "unicode-secret\u2028tail",
      "paragraph-secret\u2029tail",
      "carriage-secrettail",
      "first spaced-secret\nsecond spaced-secret",
      "first line\nsecond line",
      "first backtick\nsecond backtick",
      "dev",
    ].sort());
  });
});


describe("readDotenvSourceWithinLimit", () => {
  it("rejects sources larger than the 1 MiB masking limit", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "pi-env-mask-size-"));
    temporaryDirectories.push(directory);
    const envPath = path.join(directory, ".env");
    await writeFile(envPath, "x".repeat(1024 * 1024 + 1), "utf8");

    await expect(readDotenvSourceWithinLimit(envPath)).resolves.toBeNull();
    await expect(parseDotenvValues(envPath)).rejects.toThrow("1 MiB masking limit");
  });
});
