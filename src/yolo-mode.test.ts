import { describe, expect, it } from "vitest";

import * as yoloModeModule from "./yolo-mode";
import {
  canResolveAskPermissionRequest,
  matchesYoloAskBashPattern,
  shouldAutoApprovePermissionState,
} from "./yolo-mode";

const yoloConfig = {
  debugLog: false,
  permissionReviewLog: true,
  yoloMode: true,
  yoloAskBashPatterns: [],
};

function getBundledDenyRelaxer(): (options: any) => boolean {
  const relaxer = (yoloModeModule as Record<string, unknown>)
    .shouldRelaxBundledToolDenyInYolo;
  expect(typeof relaxer).toBe("function");
  return relaxer as (options: any) => boolean;
}

function bundledDeny(toolName: "write" | "edit") {
  return {
    toolName,
    state: "deny",
    source: "tool",
    origin: "bundled",
  } as const;
}

describe("matchesYoloAskBashPattern", () => {
  it.each([
    "rm -rf /Volumes/NvmeExt1/openimages/OpenImages/.shards",
    "rm *",
    "rm",
    "rm file.txt",
    "rm -fr path",
  ])("requires prompt for %s in YOLO mode", (command: string) => {
    const context = { toolName: "bash", command };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(true);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(false);
  });

  it.each([
    "git push origin main",
    "ssh prod.example.com",
    "docker exec -it app sh",
    "kubectl apply -f deploy.yaml",
    "aws s3 ls s3://example-bucket",
  ])("requires prompt for remote-control %s commands in YOLO mode", (command: string) => {
    const context = { toolName: "bash", command };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(true);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(false);
  });

  it("keeps non-rm bash commands auto-approvable", () => {
    const context = { toolName: "bash", command: "npm test" };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(false);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(true);
  });

  it("does not apply bash-only protection to non-bash requests", () => {
    const context = { toolName: "read", command: "rm *" };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(false);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(true);
  });
});

describe("shouldAutoApprovePermissionState", () => {
  it("does not auto-approve when forcePromptInYolo is set", () => {
    expect(
      shouldAutoApprovePermissionState("ask", yoloConfig, {
        toolName: "write",
        forcePromptInYolo: true,
      } as any),
    ).toBe(false);
  });
});

describe("shouldRelaxBundledToolDenyInYolo", () => {
  it.each(["write", "edit"] as const)(
    "relaxes bundled local %s denies in yolo",
    (toolName) => {
      const relaxer = getBundledDenyRelaxer();

      expect(
        relaxer({
          config: yoloConfig,
          toolName,
          path: "/tmp/project/file.txt",
          cwd: "/tmp/project",
          toolPermission: bundledDeny(toolName),
        }),
      ).toBe(true);
    },
  );

  it.each(["write", "edit"] as const)(
    "relaxes bundled external %s denies after external path approval",
    (toolName) => {
      const relaxer = getBundledDenyRelaxer();

      expect(
        relaxer({
          config: yoloConfig,
          toolName,
          path: "/tmp/shared/file.txt",
          cwd: "/tmp/project",
          toolPermission: bundledDeny(toolName),
          hasExternalDirectoryApproval: true,
        }),
      ).toBe(true);
    },
  );

  it("keeps first external write denied until external_directory is allowed", () => {
    const relaxer = getBundledDenyRelaxer();

    expect(
      relaxer({
        config: yoloConfig,
        toolName: "write",
        path: "/tmp/shared/file.txt",
        cwd: "/tmp/project",
        toolPermission: bundledDeny("write"),
        hasExternalDirectoryApproval: false,
      }),
    ).toBe(false);
  });

  it("keeps non-bundled denies intact", () => {
    const relaxer = getBundledDenyRelaxer();

    expect(
      relaxer({
        config: yoloConfig,
        toolName: "write",
        path: "/tmp/project/.env",
        cwd: "/tmp/project",
        toolPermission: {
          ...bundledDeny("write"),
          origin: "security-profile",
        },
      }),
    ).toBe(false);
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

  it("returns false when yolo is forced to prompt and no prompt path exists", () => {
    expect(
      canResolveAskPermissionRequest({
        config: yoloConfig,
        hasUI: false,
        isSubagent: false,
        toolName: "write",
        forcePromptInYolo: true,
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
