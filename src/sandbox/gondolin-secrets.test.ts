import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { loadGondolinSecretBindings } from "./gondolin-secrets.js";

describe("loadGondolinSecretBindings", () => {
  it("loads host values only for parent-approved host scopes", async () => {
    const agentDir = await mkdtemp(join(tmpdir(), "gondolin-secrets-agent-"));
    try {
      await writeFile(join(agentDir, "gondolin-secrets.json"), JSON.stringify({
        GITHUB_TOKEN: { hosts: ["api.github.com", "github.com"] },
        NPM_TOKEN: { hosts: ["registry.npmjs.org"] },
      }));
      const secrets = loadGondolinSecretBindings(agentDir, {
        GITHUB_TOKEN: "github-secret",
        NPM_TOKEN: "",
      });
      expect(secrets).toEqual([{ name: "GITHUB_TOKEN", value: "github-secret", hosts: ["api.github.com", "github.com"] }]);
    } finally {
      await rm(agentDir, { recursive: true, force: true });
    }
  });

  it("fails closed for malformed parent secret configuration", async () => {
    const agentDir = await mkdtemp(join(tmpdir(), "gondolin-secrets-invalid-"));
    try {
      await writeFile(join(agentDir, "gondolin-secrets.json"), JSON.stringify({ "bad-name": { hosts: ["api.example.com"] } }));
      expect(() => loadGondolinSecretBindings(agentDir, { "bad-name": "value" })).toThrow(/secret|name|invalid/i);
    } finally {
      await rm(agentDir, { recursive: true, force: true });
    }
  });

  it("does not require a config file", async () => {
    const agentDir = await mkdtemp(join(tmpdir(), "gondolin-secrets-empty-"));
    try {
      expect(loadGondolinSecretBindings(agentDir, { GITHUB_TOKEN: "value" })).toEqual([]);
    } finally {
      await rm(agentDir, { recursive: true, force: true });
    }
  });
});
