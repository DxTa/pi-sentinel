import { describe, expect, it } from "vitest";

import { summarizeEnvironmentSizes } from "./spawn-diagnostics.js";

describe("summarizeEnvironmentSizes", () => {
  it("reports UTF-8 byte counts and names without values", () => {
    const env: NodeJS.ProcessEnv = {
      SHORT: "x",
      UTF8: "🔒",
      PRIVATE: "secret-value",
    };

    const summary = summarizeEnvironmentSizes(env);

    expect(summary).toEqual({
      totalBytes:
        Buffer.byteLength("SHORT=x\0", "utf8") +
        Buffer.byteLength("UTF8=🔒\0", "utf8") +
        Buffer.byteLength("PRIVATE=secret-value\0", "utf8"),
      largestVariables: [
        { name: "PRIVATE", bytes: Buffer.byteLength("PRIVATE=secret-value\0", "utf8") },
        { name: "UTF8", bytes: Buffer.byteLength("UTF8=🔒\0", "utf8") },
        { name: "SHORT", bytes: Buffer.byteLength("SHORT=x\0", "utf8") },
      ],
    });
    expect(JSON.stringify(summary)).not.toContain("secret-value");
  });

  it("caps output at ten largest variables", () => {
    const env = Object.fromEntries(
      Array.from({ length: 12 }, (_, index) => ["VAR_" + index, "x".repeat(index + 1)]),
    ) as NodeJS.ProcessEnv;

    const summary = summarizeEnvironmentSizes(env);

    expect(summary.largestVariables).toHaveLength(10);
    expect(summary.largestVariables[0]?.name).toBe("VAR_11");
    expect(summary.largestVariables.at(-1)?.name).toBe("VAR_2");
  });
});
