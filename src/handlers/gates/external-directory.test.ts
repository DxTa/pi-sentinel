import path from "node:path";

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
    "forces a prompt in yolo for external %s tools",
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
