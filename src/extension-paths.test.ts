import { describe, expect, it } from "vitest";

import { EXTENSION_ROOT } from "./extension-config.js";
import { computeExtensionPaths } from "./extension-paths.js";

describe("computeExtensionPaths", () => {
  it("includes pi-sentinel package root as read-only infrastructure", () => {
    expect(computeExtensionPaths("/tmp/pi-sentinel-agent").piInfrastructureDirs).toContain(
      EXTENSION_ROOT,
    );
  });
});
