import { afterEach, describe, expect, it } from "vitest";

import {
  addMaskedAuthSessionGrant,
  clearMaskedAuthSessionGrants,
  getMaskedAuthSessionGrants,
} from "./masked-auth-grants.js";

afterEach(() => clearMaskedAuthSessionGrants());

describe("masked auth session grants", () => {
  it("clears grants at session end", () => {
    addMaskedAuthSessionGrant("/repo", "ssh-auth", "/home/user/.ssh/id_rsa");

    expect(getMaskedAuthSessionGrants("/repo", "ssh-auth")).toEqual([
      "/home/user/.ssh/id_rsa",
    ]);

    clearMaskedAuthSessionGrants();

    expect(getMaskedAuthSessionGrants("/repo", "ssh-auth")).toEqual([]);
  });
});
