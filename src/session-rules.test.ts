import { describe, expect, it } from "vitest";

import { evaluate } from "./rule";
import { SessionRules } from "./session-rules";

describe("SessionRules deny and remove", () => {
  it("a session deny overrides a session allow for the same pattern", () => {
    const rules = new SessionRules();
    rules.approve("bash", "git push *");
    rules.deny("bash", "git push *");

    expect(evaluate("bash", "git push origin", rules.getRuleset()).action).toBe("deny");
  });

  it("a later session allow replaces an earlier session deny", () => {
    const rules = new SessionRules();
    rules.deny("bash", "git push *");
    rules.approve("bash", "git push *");

    expect(rules.getRuleset()).toHaveLength(1);
    expect(evaluate("bash", "git push origin", rules.getRuleset()).action).toBe("allow");
  });

  it("removing a session entry restores the fallback decision", () => {
    const rules = new SessionRules();
    rules.deny("bash", "git push *");
    rules.remove("bash", "git push *");

    expect(evaluate("bash", "git push origin", rules.getRuleset()).action).toBe("ask");
  });
});
