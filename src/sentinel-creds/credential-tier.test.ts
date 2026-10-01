import { describe, expect, it } from "vitest";

import { allMatchesLowTier, isLowTierMatch } from "./credential-tier.js";
import { scanForSecrets } from "./scanner.js";

describe("isLowTierMatch", () => {
  it.each([
    ["Stripe test secret", { label: "Stripe Key", line: 1, snippet: "", value: "sk_test_" + "a".repeat(24) }],
    ["Stripe test restricted", { label: "stripe-access-token", line: 1, snippet: "", value: "rk_test_" + "b".repeat(24) }],
    ["localhost DB URL", { label: "Database URL with password", line: 1, snippet: "", value: "postgres://u:pw@localhost:5432" }],
    ["loopback DB URL", { label: "Database URL with password", line: 1, snippet: "", value: "redis://u:pw@127.0.0.1" }],
    ["IPv6 loopback DB URL", { label: "Database URL with password", line: 1, snippet: "", value: "mysql://u:pw@[::1]:3306" }],
    ["generic quoted", { label: "Generic Secret", line: 1, snippet: "" }],
    ["generic unquoted", { label: "Generic Secret (unquoted)", line: 1, snippet: "" }],
    ["env assignment", { label: "Env Assignment (quoted)", line: 1, snippet: "" }],
    ["entropy-only", { label: "High-Entropy Value", line: 1, snippet: "" }],
    ["gitleaks generic", { label: "generic-api-key", line: 1, snippet: "" }],
  ])("treats %s as low tier", (_name, match) => {
    expect(isLowTierMatch(match)).toBe(true);
  });

  it.each([
    ["Stripe live", { label: "Stripe Key", line: 1, snippet: "", value: "sk_live_" + "a".repeat(24) }],
    ["remote DB URL", { label: "Database URL with password", line: 1, snippet: "", value: "postgres://u:pw@db.example.com" }],
    ["localhost-prefixed remote host", { label: "Database URL with password", line: 1, snippet: "", value: "postgres://u:pw@localhost.evil.com" }],
    ["DB URL without host", { label: "Database URL with password", line: 1, snippet: "", value: "postgres://u:pw@" }],
    ["AWS", { label: "AWS Access Key", line: 1, snippet: "" }],
    ["PEM", { label: "PEM Private Key", line: 1, snippet: "" }],
    ["GitHub", { label: "GitHub Token", line: 1, snippet: "" }],
    ["unknown gitleaks rule", { label: "some-new-rule", line: 1, snippet: "" }],
  ])("treats %s as high tier", (_name, match) => {
    expect(isLowTierMatch(match)).toBe(false);
  });
});

describe("allMatchesLowTier", () => {
  it("requires at least one match and every match low tier", () => {
    const low = { label: "Generic Secret", line: 1, snippet: "" };
    const high = { label: "AWS Access Key", line: 2, snippet: "" };
    expect(allMatchesLowTier([])).toBe(false);
    expect(allMatchesLowTier([low])).toBe(true);
    expect(allMatchesLowTier([low, high])).toBe(false);
  });

  it("captures DB host from real scanner output", async () => {
    const result = await scanForSecrets("DATABASE_URL=postgres://app:hunter2secret@localhost:5432/app\n");
    const dbMatches = result.matches.filter((m) => m.label === "Database URL with password");
    expect(dbMatches).toHaveLength(1);
    expect(isLowTierMatch(dbMatches[0]!)).toBe(true);
  });
});
