import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

import { describeExternalDirectoryGate } from "./external-directory";

const cwd = path.join("/tmp", "project");

function expectDescriptor(result: ReturnType<typeof describeExternalDirectoryGate>) {
  expect(result).not.toBeNull();
  expect(result && !("action" in result)).toBe(true);
  if (!result || "action" in result) {
    throw new Error("Expected gate descriptor");
  }
  return result;
}

describe("describeExternalDirectoryGate", () => {
  it("does not force a prompt in yolo for external read-only tools", () => {
    const result = expectDescriptor(
      describeExternalDirectoryGate(
        {
          toolName: "read",
          agentName: "worker",
          input: { path: "../notes.txt" },
          toolCallId: "call-1",
          cwd,
        },
        [],
      ),
    );

    expect((result.promptDetails as any).forcePromptInYolo).toBeUndefined();
  });

  it.each(["write", "edit"] as const)(
    "forces a prompt in yolo-auto and manual for external %s tools",
    (toolName) => {
      const result = expectDescriptor(
        describeExternalDirectoryGate(
          {
            toolName,
            agentName: "worker",
            input: { path: "../notes.txt" },
            toolCallId: `call-${toolName}`,
            cwd,
          },
          [],
        ),
      );

      expect((result.promptDetails as any).forcePromptInYolo).toBe(true);
    },
  );

  it.each(["write", "edit"] as const)("does not force a prompt for external %s tools in yolo mode", (toolName) => {
    const result = expectDescriptor(
      describeExternalDirectoryGate(
        { toolName, agentName: "worker", input: { path: "../notes.txt" }, toolCallId: `call-${toolName}`, cwd, mode: "yolo" },
        [],
      ),
    );

    expect((result.promptDetails as any).forcePromptInYolo).toBeUndefined();
  });

  it.each(["read", "write"] as const)("treats file-URL paths as external for %s", (toolName) => {
    const workspace = mkdtempSync(path.join(tmpdir(), "pi-external-url-"));
    const outsidePath = pathToFileURL(path.join(path.dirname(workspace), "outside.txt")).href;

    try {
      const result = expectDescriptor(
        describeExternalDirectoryGate(
          {
            toolName,
            agentName: "worker",
            input: { path: outsidePath },
            toolCallId: `call-file-url-${toolName}`,
            cwd: workspace,
          },
          [],
        ),
      );
      expect(result.surface).toBe("external_directory");
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("allows a trusted Pi clipboard direct read without a permission descriptor", () => {
    const clipboardPath = "/var/folders/cg/T/pi-clipboard-b46509f4-a820-4442-9013-73da6d2739d2.png";
    const result = describeExternalDirectoryGate(
      {
        toolName: "read",
        agentName: "worker",
        input: { path: clipboardPath },
        toolCallId: "call-clipboard",
        cwd,
      },
      [],
      (pathValue) => pathValue === clipboardPath,
    );

    expect(result).toMatchObject({
      action: "allow",
      log: { event: "permission_request.clipboard_auto_allowed" },
    });
    expect(result && "decision" in result).toBe(false);
  });

  it("does not use clipboard read trust for writes", () => {
    const result = expectDescriptor(
      describeExternalDirectoryGate(
        {
          toolName: "write",
          agentName: "worker",
          input: { path: "/var/folders/cg/T/pi-clipboard-b46509f4-a820-4442-9013-73da6d2739d2.png" },
          toolCallId: "call-clipboard-write",
          cwd,
        },
        [],
        () => true,
      ),
    );

    expect((result.promptDetails as any).forcePromptInYolo).toBe(true);
  });
});

describe("describeExternalDirectoryGate protected credential reads", () => {
  it.each(["~/.ssh/id_ed25519", "~/.config/gh/hosts.yml"])("auto-allows read of %s", (target) => {
    expect(
      describeExternalDirectoryGate(
        { toolName: "read", agentName: null, input: { path: target }, toolCallId: "call-protected", cwd },
        [],
      ),
    ).toMatchObject({ action: "allow" });
  });

  it.each(["write", "edit"] as const)("still prompts for %s of a protected path", (toolName) => {
    expectDescriptor(
      describeExternalDirectoryGate(
        { toolName, agentName: null, input: { path: "~/.ssh/config" }, toolCallId: `call-${toolName}`, cwd },
        [],
      ),
    );
  });
});

describe("describeExternalDirectoryGate clipboard temp files", () => {
  it("auto-allows read of an untracked pi-clipboard file in the OS temp root", () => {
    const clipboardPath = path.join(tmpdir(), "pi-clipboard-11111111-2222-3333-4444-555555555555.png");
    writeFileSync(clipboardPath, "png");
    try {
      expect(
        describeExternalDirectoryGate(
          { toolName: "read", agentName: null, input: { path: clipboardPath }, toolCallId: "clip", cwd },
          [],
        ),
      ).toMatchObject({ action: "allow" });
    } finally {
      rmSync(clipboardPath, { force: true });
    }
  });

  it("still prompts for writes to a pi-clipboard path and reads of lookalike names", () => {
    const lookalike = path.join(tmpdir(), "pi-clipboard-not-a-uuid.png");
    writeFileSync(lookalike, "png");
    try {
      expectDescriptor(
        describeExternalDirectoryGate(
          { toolName: "read", agentName: null, input: { path: lookalike }, toolCallId: "look", cwd },
          [],
        ),
      );
      expectDescriptor(
        describeExternalDirectoryGate(
          { toolName: "write", agentName: null, input: { path: lookalike }, toolCallId: "w", cwd },
          [],
        ),
      );
    } finally {
      rmSync(lookalike, { force: true });
    }
  });
});
