import { afterEach, describe, expect, it } from "vitest";

import { checkBashNetworkPolicy } from "./domain-gate";
import {
  clearSessionDomains,
  denySessionDomains,
  removeSessionDomain,
} from "./session-domains";

const config = { unknownDomains: "ask" as const, allowedDomains: ["api.example.com"] };
const command = "curl https://api.example.com/v1";

afterEach(() => clearSessionDomains());

describe("session domain grants", () => {
  it("session deny blocks a domain that config allows", () => {
    expect(checkBashNetworkPolicy(command, config, "/repo").verdict).toBe("allowed");

    denySessionDomains(["api.example.com"]);

    expect(checkBashNetworkPolicy(command, config, "/repo").verdict).toBe("denied");
  });

  it("removing a session deny restores the config decision", () => {
    denySessionDomains(["api.example.com"]);

    removeSessionDomain("api.example.com");

    expect(checkBashNetworkPolicy(command, config, "/repo").verdict).toBe("allowed");
  });
});
