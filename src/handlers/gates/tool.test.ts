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

describe("describeToolGate bash session approval", () => {
  it("offers one session pattern per compound segment", () => {
    const descriptor = describeToolGate(
      context("bash", { command: "cd src && pytest -q && cd .." }),
      { ...check("bash"), command: "cd src && pytest -q && cd .." },
    );
    expect(descriptor.sessionApproval).toEqual({ surface: "bash", patterns: ["cd *", "pytest *"] });
  });

  it("keeps a single pattern for simple commands", () => {
    const descriptor = describeToolGate(context("bash", { command: "pytest -q" }), { ...check("bash"), command: "pytest -q" });
    expect(descriptor.sessionApproval).toEqual({ surface: "bash", pattern: "pytest *" });
  });
});

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

  it("carries a privacy-safe hard-rule result for safe and sensitive paths", () => {
    const workspace = process.cwd();
      const safe = describeToolGate(
        { ...context("read", { path: "README.md" }), cwd: workspace },
        check("read"),
      );
      expect(safe.promptDetails).toMatchObject({
        yoloAutoEligible: true,
        yoloAutoHardRuleHit: false,
      });
      expect(safe.promptDetails).not.toHaveProperty("path");
      expect(JSON.stringify(safe.promptDetails)).not.toContain(workspace);

      const sensitive = describeToolGate(
        { ...context("read", { path: "/etc/hosts" }), cwd: workspace },
        check("read"),
      );
      expect(sensitive.promptDetails).toMatchObject({
        yoloAutoEligible: false,
        yoloAutoHardRuleHit: true,
      });

      const listing = describeToolGate(
        { ...context("ls", {}), cwd: workspace },
        check("ls"),
      );
      expect(listing.promptDetails).toMatchObject({
        yoloAutoEligible: true,
        yoloAutoHardRuleHit: false,
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

});


describe("describeToolGate yolo-auto write/edit candidates", () => {
  it.each(["write", "edit"] as const)(
    "passes only the first 800 replacement characters for %s",
    (toolName) => {
      const content = "x".repeat(801);
      const path = toolName === "write" ? "notes.txt" : "src/index.ts";
      const input = toolName === "write"
        ? { path, content }
        : { path, edits: [{ oldText: "old", newText: content }] };
      const descriptor = describeToolGate(context(toolName, input), check(toolName));

      expect(descriptor.promptDetails).toMatchObject({
        yoloAutoEligible: true,
        yoloAutoWorkspaceLocal: true,
        yoloAutoWorkspaceRelativePath: path,
        yoloAutoOperation: toolName,
        yoloAutoText: "tool=" + toolName + " path=" + path + " content=" + "x".repeat(800),
        yoloAutoTextTruncated: true,
      });
      expect(JSON.stringify(descriptor.promptDetails)).not.toContain(process.cwd());
    },
  );

  it("keeps writes outside the workspace ineligible", () => {
    const descriptor = describeToolGate(
      context("write", { path: "../outside.txt", content: "secret" }),
      check("write"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: false,
      yoloAutoWorkspaceLocal: false,
    });
  });

  it("does not make an allowed write a yolo-auto candidate", () => {
    const descriptor = describeToolGate(
      context("write", { path: "notes.txt", content: "content" }),
      check("write", "allow"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: false,
      yoloAutoOperation: "write",
    });
  });
});


describe("describeToolGate yolo-auto Bash eligibility", () => {
  it("passes redacted command text only for a sandboxed workspace-local ask", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command: "printf safe" }), sandboxed: true, yoloAutoHardRuleHit: false, yoloAutoWorkspaceLocal: true, yoloAutoCommand: "printf safe" },
      check("bash"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: true,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "exec",
      yoloAutoSandboxed: true,
      yoloAutoHardRuleHit: false,
      yoloAutoText: "tool=bash command=printf safe",
      yoloAutoTextTruncated: false,
    });
  });

  it("keeps host Bash ineligible while preserving safe workspace metadata", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command: "ls" }), sandboxed: false, yoloAutoHardRuleHit: false, yoloAutoWorkspaceLocal: true, yoloAutoCommand: "ls" },
      check("bash"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: false,
      yoloAutoWorkspaceLocal: true,
      yoloAutoOperation: "exec",
      yoloAutoSandboxed: false,
      yoloAutoHardRuleHit: false,
    });
  });

  it("keeps sensitive Bash paths out of classifier text", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command: "cat /etc/hosts" }), sandboxed: true, yoloAutoHardRuleHit: true, yoloAutoWorkspaceLocal: false, yoloAutoCommand: "cat <sensitive-path>" },
      check("bash"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      yoloAutoEligible: false,
      yoloAutoWorkspaceLocal: false,
      yoloAutoHardRuleHit: true,
    });
    expect(descriptor.promptDetails).not.toHaveProperty("yoloAutoText");
  });
});
