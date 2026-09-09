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
});
