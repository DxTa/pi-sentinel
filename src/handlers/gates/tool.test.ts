import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { describeToolGate } from "./tool";
import type { ToolCallContext } from "./types";

function context(toolName: string, input: unknown): ToolCallContext {
  return {
    toolName,
    input,
    agentName: null,
    toolCallId: "tool-1",
    cwd: process.cwd(),
  };
}

function check(toolName: string, state: "allow" | "deny" | "ask" = "ask") {
  return {
    toolName,
    state,
    source: "tool" as const,
    origin: "builtin" as const,
  };
}

describe("describeToolGate yolo-auto eligibility", () => {
  it("marks workspace-local read requests after deterministic gates", () => {
    const descriptor = describeToolGate(
      context("read", { path: "README.md" }),
      check("read"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: true,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "read",
    });
  });

  it("does not mark external reads eligible", () => {
    const descriptor = describeToolGate(
      context("read", { path: "../secrets.txt" }),
      check("read"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: false,
      yoloAutoWorkspaceLocal: false,
      yoloAutoOperation: "read",
    });
  });


  it("rejects symlinked reads whose canonical target leaves workspace", () => {
    const workspace = mkdtempSync(join(tmpdir(), "pi-yolo-workspace-"));
    const outside = mkdtempSync(join(tmpdir(), "pi-yolo-outside-"));
    const secret = join(outside, "secret.txt");
    const link = join(workspace, "link.txt");
    writeFileSync(secret, "secret");
    symlinkSync(secret, link);

    try {
      const descriptor = describeToolGate(
        { ...context("read", { path: "link.txt" }), cwd: workspace },
        check("read"),
      );
      expect(descriptor.promptDetails).toMatchObject({
        yoloAutoEligible: false,
        yoloAutoWorkspaceLocal: false,
      });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("marks pathless directory listings as workspace-local list operations", () => {
    const descriptor = describeToolGate(context("ls", {}), check("ls"));

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: true,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "list",
    });
  });

  it("never marks writes eligible", () => {
    const descriptor = describeToolGate(
      context("write", { path: "notes.txt", content: "x" }),
      check("write"),
    );

    expect(descriptor.promptDetails).not.toHaveProperty("yoloAutoEligible");
  });
});
