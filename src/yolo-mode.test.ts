import { describe, expect, it } from "vitest";

import * as yoloModeModule from "./yolo-mode";
import {
  canResolveAskPermissionRequest,
  matchesGitPushCommand,
  matchesYoloAskBashPattern,
  shouldAutoApproveForwardedPermissionRequest,
  shouldAutoApprovePermissionState,
} from "./yolo-mode";

const yoloConfig = {
  debugLog: false,
  permissionReviewLog: true,
  mode: "yolo",
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


describe("matchesGitPushCommand", () => {
  it.each([
    "git push origin main",
    "git -C repo push origin main",
    "/usr/bin/git push origin main",
    "git status && git push origin main",
    "bash -c 'git push origin main'",
    'git "push" origin main',
    "git pu'sh' origin main",
    '"git" "-C" repo "push" origin main',
    "git -C '$repo' push origin main",
  ])("recognizes %s", (command) => {
    expect(matchesGitPushCommand(command)).toBe(true);
  });

  it.each([
    "git pull",
    "git status",
    "echo git push origin main",
    "$bin/git push origin main",
    "git -${opt} push origin main",
  ])(
    "does not recognize %s",
    (command) => {
      expect(matchesGitPushCommand(command)).toBe(false);
    },
  );
});

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
    "git -C repo push origin main",
    "ssh prod.example.com",
    "kubectl apply -f deploy.yaml",
    "kubectl set image deploy/a a=b",
    "kubectl delete pod a",
    "kubectl -n prod delete pod a",
    "kubectl --context prod scale deploy/a --replicas=2",
    "kubectl rollout restart deploy/a",
    "kubectl uncordon node-a",
    "kubectl autoscale deploy a --max=3",
    "kubectl run x --image=y",
    "kubectl expose deploy a --port=80",
    "kubectl --as admin delete pod a",
    "/bin/rm ./notes.txt",
    "/usr/bin/ssh host",
    "rm\t./notes.txt",
    "sudo git push origin main",
    "git -c user.name=x push origin main",
  ])("requires prompt for %s in YOLO mode", (command: string) => {
    const context = { toolName: "bash", command };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(true);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(false);
  });

  it.each([
    "cd src && rm -rf build",
    "git status; git push origin main",
    "for f in a b; do rm $f; done",
    "if true; then kubectl delete pod a; fi",
    "bash -c 'rm x'",
    "ls | xargs rm",
    "find . -name x -exec rm {} +",
    "sudo rm x",
  ])("requires prompt when %j hides a built-in ask pattern", (command: string) => {
    const context = { toolName: "bash", command };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(true);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(false);
  });

  it("applies user ask patterns to inner commands too", () => {
    const config = { ...yoloConfig, yoloAskBashPatterns: ["make deploy *"] };

    expect(matchesYoloAskBashPattern({ toolName: "bash", command: "cd app && make deploy prod" }, config)).toBe(true);
    expect(matchesYoloAskBashPattern({ toolName: "bash", command: "cd app && make test" }, config)).toBe(false);
  });

  it("keeps ordinary compound commands auto-approvable", () => {
    for (const command of ["cd src && npm test", "for f in a b; do echo $f; done", "ls | grep x"]) {
      expect(matchesYoloAskBashPattern({ toolName: "bash", command }, yoloConfig), command).toBe(false);
    }
  });

  it.each([
    "docker exec -it app sh",
    "aws s3 ls s3://example-bucket",
    "gh pr list",
    "scp a host:b",
    "rsync -a a b",
    "terraform plan",
    "git pull",
    "git clone https://example.test/r.git",
    "git fetch",
    "kubectl get pods",
    "kubectl -n prod describe pod a",
    "kubectl logs deploy/a",
    "kubectl get configmap apply",
    "kubectl rollout status deploy/a",
    "kubectl rollout history deploy/a",
    "git log --grep push",
  ])("lets %s through in YOLO mode", (command: string) => {
    const context = { toolName: "bash", command };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(false);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(true);
  });

  it("keeps non-rm bash commands auto-approvable", () => {
    const context = { toolName: "bash", command: "npm test" };

    expect(matchesYoloAskBashPattern(context, yoloConfig)).toBe(false);
    expect(shouldAutoApprovePermissionState("ask", yoloConfig, context)).toBe(true);
  });

  it("keeps classic yolo bypass enabled in yolo-auto mode", () => {
    expect(shouldAutoApprovePermissionState("ask", {
      ...yoloConfig,
      mode: "yolo-auto",
    }, { toolName: "read" })).toBe(true);
  });

  it("does not auto-approve forwarded requests in yolo-auto mode", () => {
    expect(shouldAutoApproveForwardedPermissionRequest(
      { ...yoloConfig, mode: "yolo-auto" },
      { toolName: "read" },
    )).toBe(false);
  });

  it("keeps classic yolo auto-approval for forwarded requests", () => {
    expect(shouldAutoApproveForwardedPermissionRequest(
      yoloConfig,
      { toolName: "read" },
    )).toBe(true);
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
          path: `${process.cwd()}/file.txt`,
          cwd: process.cwd(),
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

  it.each(["write", "edit"] as const)("relaxes a bundled external %s deny in yolo without a prior approval", (toolName) => {
    const relaxer = getBundledDenyRelaxer();

    expect(
      relaxer({
        config: yoloConfig,
        toolName,
        path: "/tmp/shared/file.txt",
        cwd: "/tmp/project",
        toolPermission: bundledDeny(toolName),
        hasExternalDirectoryApproval: false,
      }),
    ).toBe(true);
  });

  it("keeps the first external write denied in yolo-auto until external_directory is allowed", () => {
    const relaxer = getBundledDenyRelaxer();

    expect(
      relaxer({
        config: { ...yoloConfig, mode: "yolo-auto" },
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
          mode: "yolo",
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
          mode: "yolo",
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
