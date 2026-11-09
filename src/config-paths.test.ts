import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { getGlobalConfigPath, getProjectConfigPath } from "./config-paths";

describe("config paths", () => {
  it("uses sentinel.json for the global and project config files", () => {
    expect(getGlobalConfigPath("/home/u/.pi/agent")).toBe(join("/home/u/.pi/agent", "sentinel.json"));
    expect(getProjectConfigPath("/work/repo")).toBe(join("/work/repo", ".pi", "sentinel.json"));
  });
});
