import { describe, expect, it } from "vitest";

import {
  canResolveAskPermissionRequest,
  matchesYoloAskBashPattern,
  shouldAutoApprovePermissionState,
} from "./yolo-mode";

describe("matchesYoloAskBashPattern", () => {
  const config = {
    debugLog: false,
    permissionReviewLog: true,
    yoloMode: true,
    yoloAskBashPatterns: [],
  };

  it.each([
    "rm -rf /Volumes/NvmeExt1/openimages/OpenImages/.shards",
    "rm *",
    "rm",
    "rm file.txt",
    "rm -fr path",
  ])("requires prompt for %s in YOLO mode", (command: string) => {
    const context = { toolName: "bash", command };

    expect(matchesYoloAskBashPattern(context, config)).toBe(true);
    expect(shouldAutoApprovePermissionState("ask", config, context)).toBe(false);
  });

  it("keeps non-rm bash commands auto-approvable", () => {
    const context = { toolName: "bash", command: "npm test" };

    expect(matchesYoloAskBashPattern(context, config)).toBe(false);
    expect(shouldAutoApprovePermissionState("ask", config, context)).toBe(true);
  });

  it("does not apply bash-only protection to non-bash requests", () => {
    const context = { toolName: "read", command: "rm *" };

    expect(matchesYoloAskBashPattern(context, config)).toBe(false);
    expect(shouldAutoApprovePermissionState("ask", config, context)).toBe(true);
  });
});

describe("canResolveAskPermissionRequest", () => {
  it("returns false for matching bash yolo exceptions when no prompt path exists", () => {
    expect(
      canResolveAskPermissionRequest({
        config: {
          debugLog: false,
          permissionReviewLog: true,
          yoloMode: true,
          yoloAskBashPatterns: ["git push *"],
        },
        hasUI: false,
        isSubagent: false,
        toolName: "bash",
        command: "git push origin main",
      } as any),
    ).toBe(false);
  });

  it("still returns true for nonmatching yolo bash commands", () => {
    expect(
      canResolveAskPermissionRequest({
        config: {
          debugLog: false,
          permissionReviewLog: true,
          yoloMode: true,
          yoloAskBashPatterns: ["git push *"],
        },
        hasUI: false,
        isSubagent: false,
        toolName: "bash",
        command: "npm test",
      } as any),
    ).toBe(true);
  });
});
