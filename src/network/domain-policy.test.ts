import { describe, expect, it } from "vitest";

import { blockedDomains } from "./domain-policy";

describe("blockedDomains", () => {
  it("keeps explicit denies active when policy is disabled", () => {
    expect(
      blockedDomains(["api.example.com"], {
        enabled: false,
        unknownDomains: "allow",
        allowedDomains: [],
        deniedDomains: ["api.example.com"],
      }),
    ).toMatchObject({
      verdict: "denied",
      blockedDomains: ["api.example.com"],
      askDomains: [],
    });
  });

  it("keeps broader denies ahead of more specific allows", () => {
    expect(
      blockedDomains(["api.example.com"], {
        enabled: true,
        unknownDomains: "deny",
        allowedDomains: ["api.example.com"],
        deniedDomains: ["*.example.com"],
      }),
    ).toEqual({
      verdict: "denied",
      blockedDomains: ["api.example.com"],
      askDomains: [],
      reason:
        'Domain gate blocked network access to "api.example.com". Remove from deniedDomains or configure network policy.',
    });
  });

  it("prefers more specific deny over broader allow", () => {
    expect(
      blockedDomains(["api.example.com"], {
        enabled: true,
        unknownDomains: "allow",
        allowedDomains: ["*.example.com"],
        deniedDomains: ["api.example.com"],
      }),
    ).toEqual({
      verdict: "denied",
      blockedDomains: ["api.example.com"],
      askDomains: [],
      reason:
        'Domain gate blocked network access to "api.example.com". Remove from deniedDomains or configure network policy.',
    });
  });
});
