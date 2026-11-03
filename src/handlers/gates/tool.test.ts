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
    expect(descriptor.promptDetails.sessionLabel).toBe('Yes, allow bash "cd *", "pytest *" for this session');
  });

  it("keeps a single pattern for simple commands", () => {
    const descriptor = describeToolGate(context("bash", { command: "pytest -q" }), { ...check("bash"), command: "pytest -q" });
    expect(descriptor.sessionApproval).toEqual({ surface: "bash", pattern: "pytest *" });
  });

  it("requires one-time approval for git push", () => {
    const descriptor = describeToolGate(
      context("bash", { command: "git push origin main" }),
      { ...check("bash"), command: "git push origin main" },
    );

    expect(descriptor).toMatchObject({
      freshApproval: true,
      promptDetails: { allowSession: false },
    });
    expect(descriptor.sessionApproval).toBeUndefined();
  });
});

describe("describeToolGate git push by mode", () => {
  const command = "git push origin main";

  it("keeps the fresh push prompt in auto so the model evaluator cannot approve it", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command }), mode: "auto" },
      { ...check("bash"), command },
    );

    expect(descriptor.promptDetails.forcePromptInYolo).toBe(true);
  });

  it("does not force the push prompt in plain yolo, which auto-approves it", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command }), mode: "yolo" },
      { ...check("bash"), command },
    );

    expect(descriptor.promptDetails.forcePromptInYolo).toBeUndefined();
  });
});

describe("describeToolGate bash approvals use inner commands", () => {
  const gate = (command: string) =>
    describeToolGate(context("bash", { command }), { ...check("bash"), command });

  it("stores the inner command of a loop, not the loop keywords", () => {
    const descriptor = gate("for f in a b; do rm $f; done");
    expect(descriptor.sessionApproval).toEqual({ surface: "bash", pattern: "rm *" });
    expect(descriptor.promptDetails.sessionLabel).toContain('"rm *"');
    expect(descriptor.promptDetails.sessionLabel).not.toContain('"for *"');
  });

  it("stores each distinct inner command of a wrapped chain", () => {
    expect(gate("cd src && bash -c 'pytest -q && rm -rf build'").sessionApproval).toEqual({
      surface: "bash",
      patterns: ["cd *", "pytest *", "rm *"],
    });
  });

  it.each(['eval "$x"', "python3 -c 'import os'", "ls && bash", "sudo rm -rf build", "find . -exec rm {} \\;", 'echo "$(id)"'])(
    "stores nothing for %j and says so",
    (command) => {
      const descriptor = gate(command);
      expect(descriptor.sessionApproval).toEqual({ surface: "bash", patterns: [] });
      expect(descriptor.promptDetails.sessionLabel).toContain("not remembered");
    },
  );
});

describe("describeToolGate auto eligibility", () => {
  it("marks workspace-local read requests after deterministic gates", () => {
    const descriptor = describeToolGate(
      context("read", { path: "README.md" }),
      check("read"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: true,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "read",
    });
  });

  it("carries a privacy-safe hard-rule result for safe and sensitive paths", () => {
    const workspace = process.cwd();
      const safe = describeToolGate(
        { ...context("read", { path: "README.md" }), cwd: workspace },
        check("read"),
      );
      expect(safe.promptDetails).toMatchObject({
        autoModeEligible: true,
        autoModeHardRuleHit: false,
      });
      expect(safe.promptDetails).not.toHaveProperty("path");
      expect(JSON.stringify(safe.promptDetails)).not.toContain(workspace);

      const sensitive = describeToolGate(
        { ...context("read", { path: "/etc/hosts" }), cwd: workspace },
        check("read"),
      );
      expect(sensitive.promptDetails).toMatchObject({
        autoModeEligible: false,
        autoModeHardRuleHit: true,
      });

      const listing = describeToolGate(
        { ...context("ls", {}), cwd: workspace },
        check("ls"),
      );
      expect(listing.promptDetails).toMatchObject({
        autoModeEligible: true,
        autoModeHardRuleHit: false,
      });
  });

  it("marks workspace-local host Bash eligible unless it uses command substitution", () => {
    const workspace = process.cwd();
    const bash = (command: string) => describeToolGate(
      { ...context("bash", { command }), cwd: workspace, sandboxed: false, autoModeWorkspaceLocal: true, autoModeCommand: command, autoModeHardRuleHit: false },
      check("bash"),
    ).promptDetails;

    expect(bash("cd src && grep -n \"a\\|b\" index.ts")).toMatchObject({ autoModeEligible: true, autoModeSandboxed: false });
    expect(bash("cat $(echo x)")).toMatchObject({ autoModeEligible: false });
  });

  it("passes the redacted inner commands to the evaluator", () => {
    const details = describeToolGate(
      { ...context("bash", { command: "cd src && rm x" }), cwd: process.cwd(), sandboxed: false, autoModeWorkspaceLocal: true,
        autoModeCommand: "cd src && rm x", autoModeHardRuleHit: false, autoModeUnits: ["cd src", "rm x"], autoModeOpaque: false },
      check("bash"),
    ).promptDetails;

    expect(details).toMatchObject({ autoModeUnits: ["cd src", "rm x"], autoModeOpaque: false });
  });

  it("keeps elevated Bash away from auto but leaves unreadable code to the model", () => {
    const workspace = process.cwd();
    const bash = (command: string, sandboxed: boolean) => describeToolGate(
      { ...context("bash", { command }), cwd: workspace, sandboxed, autoModeWorkspaceLocal: true, autoModeCommand: command, autoModeHardRuleHit: false },
      check("bash"),
    ).promptDetails;

    expect(bash("sudo rm -rf build", false)).toMatchObject({ autoModeEligible: false });
    expect(bash("sudo rm -rf build", true)).toMatchObject({ autoModeEligible: false });
    expect(bash("python3 -c 'print(1)'", false)).toMatchObject({ autoModeEligible: true });
  });

  it("does not mark external reads eligible", () => {
    const descriptor = describeToolGate(
      context("read", { path: "../secrets.txt" }),
      check("read"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: false,
      autoModeWorkspaceLocal: false,
      autoModeOperation: "read",
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
        autoModeEligible: false,
        autoModeWorkspaceLocal: false,
      });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("marks pathless directory listings as workspace-local list operations", () => {
    const descriptor = describeToolGate(context("ls", {}), check("ls"));

    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: true,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "list",
    });
  });

});


describe("describeToolGate auto write/edit candidates", () => {
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
        autoModeEligible: true,
        autoModeWorkspaceLocal: true,
        autoModeWorkspaceRelativePath: path,
        autoModeOperation: toolName,
        autoModeText: "tool=" + toolName + " path=" + path + " content=" + "x".repeat(800),
        autoModeTextTruncated: true,
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
      autoModeEligible: false,
      autoModeWorkspaceLocal: false,
    });
  });

  it("does not make an allowed write a auto candidate", () => {
    const descriptor = describeToolGate(
      context("write", { path: "notes.txt", content: "content" }),
      check("write", "allow"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: false,
      autoModeOperation: "write",
    });
  });
});


describe("describeToolGate auto Bash eligibility", () => {
  it("passes redacted command text only for a sandboxed workspace-local ask", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command: "printf safe" }), sandboxed: true, autoModeHardRuleHit: false, autoModeWorkspaceLocal: true, autoModeCommand: "printf safe" },
      check("bash"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: true,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "exec",
      autoModeSandboxed: true,
      autoModeHardRuleHit: false,
      autoModeText: "tool=bash command=printf safe",
      autoModeTextTruncated: false,
    });
  });

  it("marks workspace-local host Bash eligible with safe workspace metadata", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command: "ls" }), sandboxed: false, autoModeHardRuleHit: false, autoModeWorkspaceLocal: true, autoModeCommand: "ls" },
      check("bash"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: true,
      autoModeWorkspaceLocal: true,
      autoModeOperation: "exec",
      autoModeSandboxed: false,
      autoModeHardRuleHit: false,
    });
  });

  it("keeps sensitive Bash paths out of classifier text", () => {
    const descriptor = describeToolGate(
      { ...context("bash", { command: "cat /etc/hosts" }), sandboxed: true, autoModeHardRuleHit: true, autoModeWorkspaceLocal: false, autoModeCommand: "cat <sensitive-path>" },
      check("bash"),
    );

    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: false,
      autoModeWorkspaceLocal: false,
      autoModeHardRuleHit: true,
    });
    expect(descriptor.promptDetails).not.toHaveProperty("autoModeText");
  });
});

describe("describeToolGate MCP auto eligibility", () => {
  it("sends MCP tool calls to the model as operation tool", () => {
    const descriptor = describeToolGate(context("mcp__github__get_issue", { owner: "acme", issue_number: 12 }), check("mcp__github__get_issue"));
    expect(descriptor.promptDetails).toMatchObject({
      autoModeEligible: true,
      autoModeWorkspaceLocal: true,
      autoModeHardRuleHit: false,
      autoModeOperation: "tool",
    });
    expect(descriptor.promptDetails.autoModeText).toContain("mcp__github__get_issue");
  });

  it("keeps MCP calls out of auto mode when policy does not ask", () => {
    expect(describeToolGate(context("mcp__github__get_issue", {}), check("mcp__github__get_issue", "allow")).promptDetails)
      .toMatchObject({ autoModeEligible: false });
  });

  it("prompts MCP calls whose arguments overflow the model window", () => {
    const descriptor = describeToolGate(context("mcp__docs__search", { query: "x".repeat(900) }), check("mcp__docs__search"));
    expect(descriptor.promptDetails).toMatchObject({ autoModeEligible: false, autoModeWorkspaceLocal: false });
    expect(descriptor.promptDetails.autoModeText).toBeUndefined();
  });

  it("does not treat other extension tools as MCP", () => {
    expect(describeToolGate(context("codemode", { code: "return 1" }), check("codemode")).promptDetails.autoModeOperation)
      .toBeUndefined();
  });
});
