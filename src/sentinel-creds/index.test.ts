import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { PromptWaitTracker } from "../prompt-state";
import { registerSentinelCreds } from "./index";
import {
  ASK_USER_BLOCKED_EVENT,
  ASK_USER_PROMPT_EVENT,
} from "./prompt";

type Handler = (event: any, ctx: any) => unknown | Promise<unknown>;

type Harness = {
  handlers: Map<string, Handler[]>;
  emitted: Array<{ channel: string; payload: unknown }>;
  selected: { title: string; options: string[] }[];
  auditLogPath: string;
};

function createHarness(
  overrides: Record<string, unknown> = {},
  configLoader?: (cwd?: string) => Record<string, unknown>,
  dependencyOverrides: Record<string, unknown> = {},
): Harness {
  const handlers = new Map<string, Handler[]>();
  const emitted: Array<{ channel: string; payload: unknown }> = [];
  const selected: { title: string; options: string[] }[] = [];
  const auditLogPath = join(mkdtempSync(join(tmpdir(), "sentinel-audit-")), "audit.jsonl");
  const eventBus = {
    emit(channel: string, payload: unknown) {
      emitted.push({ channel, payload });
    },
    on() {
      return () => undefined;
    },
  };
  const pi = {
    on(name: string, handler: Handler) {
      handlers.set(name, [...(handlers.get(name) ?? []), handler]);
    },
    events: eventBus,
  };

  registerSentinelCreds(pi as never, {
    promptWaitTracker: new PromptWaitTracker(eventBus),
    getConfig: configLoader ?? (() => ({
      sentinelCreds: {
        enabled: true,
        auditLogPath,
        ...overrides,
      },
    })),
    ...dependencyOverrides,
  });

  return { handlers, emitted, selected, auditLogPath };
}

function createContext(
  selected: Harness["selected"],
  cwd = tmpdir(),
  selection: string | undefined = "Deny",
  selectError?: Error,
) {
  return {
    hasUI: true,
    cwd,
    ui: {
      async select(title: string, options: string[]) {
        selected.push({ title, options });
        if (selectError) throw selectError;
        return selection;
      },
      setStatus() {
        return undefined;
      },
    },
  };
}

function promptEvents(harness: Harness) {
  return harness.emitted.filter(
    ({ channel }) => channel === ASK_USER_PROMPT_EVENT || channel === ASK_USER_BLOCKED_EVENT,
  );
}

async function runToolCall(harness: Harness, event: unknown, ctx: unknown): Promise<unknown> {
  let result: unknown;
  for (const handler of harness.handlers.get("tool_call") ?? []) {
    const next = await handler(event, ctx);
    if (next !== undefined) result = next;
  }
  return result;
}

async function runToolResult(harness: Harness, event: unknown, ctx: unknown = {}): Promise<unknown> {
  let result: unknown;
  for (const handler of harness.handlers.get("tool_result") ?? []) {
    const next = await handler(event, ctx);
    if (next !== undefined) result = next;
  }
  return result;
}

describe("sentinel-creds structured prompt integration", () => {
  it("allows eligible secret reads through shared yolo-auto without raw-read allowance", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-yolo-secret-"));
    const secretPath = join(root, "secret.env");
    writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${["AKIA", "1234567890ABCDEF"].join("")}\n`, "utf8");
    const evaluate = vi.fn(async () => ({
      action: "allow" as const,
      reason: "safe_workspace_read",
      candidate: true,
      attempted: true,
      evaluationId: "secret-eval-1",
    }));
    const harness = createHarness(
      { envShield: false, scanBashReads: false, resultScanning: true },
      () => ({ sentinelCreds: { enabled: true, envShield: false, scanBashReads: false, resultScanning: true } }),
      {
        getPermissionConfig: () => ({ mode: "yolo-auto", yoloAutoMaxLevel: "l1" }),
        yoloAutoEvaluator: { evaluate },
      },
    );

    const result = await runToolCall(
      harness,
      { toolCallId: "secret-model-allow", toolName: "read", input: { path: secretPath } },
      { hasUI: true, cwd: root, ui: { select: vi.fn(), setStatus() {} } },
    );

    expect(result).toBeUndefined();
    expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({
      flow: "secret_read",
      candidate: true,
      operation: "read",
      workspaceLocal: true,
      toolCallIdPresent: true,
    }));
    expect(evaluate.mock.calls[0][0]).not.toHaveProperty("workspaceRelativePath");
    expect(JSON.stringify(evaluate.mock.calls[0])).not.toContain(root);
  });

  it("blocks headless eligible secret reads when model does not allow", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-yolo-secret-"));
    const secretPath = join(root, "secret.env");
    writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${["AKIA", "1234567890ABCDEF"].join("")}\n`, "utf8");
    const evaluate = vi.fn(async () => ({
      action: "prompt" as const,
      reason: "l1_request_failed",
      candidate: true,
      attempted: true,
      evaluationId: "secret-eval-2",
    }));
    const harness = createHarness(
      { envShield: false, scanBashReads: false, resultScanning: true },
      () => ({ sentinelCreds: { enabled: true, envShield: false, scanBashReads: false, resultScanning: true } }),
      {
        getPermissionConfig: () => ({ mode: "yolo-auto", yoloAutoMaxLevel: "l1" }),
        yoloAutoEvaluator: { evaluate },
      },
    );

    const result = await runToolCall(
      harness,
      { toolCallId: "secret-model-failure", toolName: "read", input: { path: secretPath } },
      { hasUI: false, cwd: root, ui: { select: vi.fn(), setStatus() {} } },
    );

    expect(result).toMatchObject({ block: true });
    expect(evaluate).toHaveBeenCalledOnce();
  });

  it("uses structured prompt metadata for credential paste", async () => {
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      resultScanning: false,
    });

    await harness.handlers.get("input")?.[0](
      { source: "interactive", text: "api_key=abcdefghijklmnop" },
      createContext(harness.selected),
    );

    const prompt = harness.emitted.find(({ channel }) => channel === ASK_USER_PROMPT_EVENT);
    expect(prompt?.payload).toMatchObject({
      questions: [{
        header: "Credential paste",
        question: "Paste this message anyway?",
        multiSelect: false,
        options: [
          { label: "Paste anyway", hasPreview: false },
          { label: "Cancel", hasPreview: false },
        ],
      }],
    });
    expect(harness.selected[0]?.options).toEqual(["Paste anyway", "Cancel"]);
    expect(promptEvents(harness).at(-1)).toEqual({
      channel: ASK_USER_BLOCKED_EVENT,
      payload: { active: false },
    });
  });

  it("uses structured prompt metadata for secret file reads", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-read-"));
    const secretPath = join(root, "secret.env");
    writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${["AKIA", "1234567890ABCDEF"].join("")}\n`, "utf8");
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      resultScanning: false,
    });

    const result = await runToolCall(
      harness,
      { toolName: "read", input: { path: secretPath } },
      createContext(harness.selected, root),
    );

    expect(result).toMatchObject({ block: true });
    const prompt = harness.emitted.find(({ channel }) => channel === ASK_USER_PROMPT_EVENT);
    expect(prompt?.payload).toMatchObject({
      questions: [{ header: "Secret read", question: "Allow reading this file?" }],
    });
    expect(JSON.stringify(prompt?.payload)).not.toContain("AKIA1234567890ABCD");
    expect(harness.selected[0]?.options).toEqual([
      "Allow once",
      "Allow for this workspace",
      "Allow globally",
      "Deny",
    ]);
    expect(harness.emitted.filter(({ channel }) => channel === "herdr:blocked")).toEqual([
      {
        channel: "herdr:blocked",
        payload: { active: true, label: "Waiting for secret-read approval" },
      },
      {
        channel: "herdr:blocked",
        payload: { active: false, label: "Waiting for secret-read approval" },
      },
    ]);
  });

  it.each([".env", ".env.local", ".env.example"])(
    "auto-reads workspace %s files while masking detected credentials",
    async (fileName) => {
      const root = mkdtempSync(join(tmpdir(), "sentinel-env-read-"));
      const secret = ["AKIA", "1234567890ABCDEF"].join("");
      const secretPath = join(root, fileName);
      writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${secret}\n`, "utf8");
      const harness = createHarness({
        envShield: false,
        scanBashReads: false,
        resultScanning: true,
      });
      const context = createContext(harness.selected, root);

      const callResult = await runToolCall(
        harness,
        { toolCallId: `env-${fileName}`, toolName: "read", input: { path: secretPath } },
        context,
      );
      const result = await runToolResult(
        harness,
        {
          toolCallId: `env-${fileName}`,
          toolName: "read",
          input: { path: secretPath },
          content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
          isError: false,
        },
        context,
      );

      expect(callResult).toBeUndefined();
      expect(harness.selected).toEqual([]);
      expect(result).toEqual({
        content: [{ type: "text", text: "AWS_ACCESS_KEY_ID=[REDACTED: AWS Access Key]" }],
      });
    },
  );

  it("does not auto-read workspace env files when result scanning is disabled", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-env-read-"));
    const secretPath = join(root, ".env.local");
    writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${["AKIA", "1234567890ABCDEF"].join("")}\n`, "utf8");
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      resultScanning: false,
    });

    const result = await runToolCall(
      harness,
      { toolName: "read", input: { path: secretPath } },
      createContext(harness.selected, root),
    );

    expect(result).toMatchObject({ block: true });
    expect(harness.selected).toHaveLength(1);
  });

  it("uses structured prompt metadata for environment exposure", async () => {
    const harness = createHarness({
      envShield: true,
      scanBashReads: false,
      resultScanning: false,
    });

    await runToolCall(
      harness,
      { toolName: "bash", input: { command: "env" } },
      createContext(harness.selected),
    );

    const prompt = harness.emitted.find(({ channel }) => channel === ASK_USER_PROMPT_EVENT);
    expect(prompt?.payload).toMatchObject({
      questions: [{ header: "Env exposure", question: "Allow this command to expose environment variables?" }],
    });
    expect(harness.selected[0]?.options).toEqual(["Allow once", "Deny"]);
  });

  it("uses structured prompt metadata for secret searches", async () => {
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      resultScanning: false,
    });

    const pattern = "password=TEST_VALUE_SHOULD_NOT_PERSIST";
    const result = await runToolCall(
      harness,
      { toolName: "grep", input: { path: ".", pattern } },
      createContext(harness.selected),
    );

    expect(result).toMatchObject({ block: true });
    expect(readFileSync(harness.auditLogPath, "utf8")).not.toContain(pattern);
    const prompt = harness.emitted.find(({ channel }) => channel === ASK_USER_PROMPT_EVENT);
    expect(prompt?.payload).toMatchObject({
      questions: [{ header: "Secret search", question: "Allow this search?" }],
    });
    expect(harness.selected[0]?.options).toEqual(["Allow once", "Deny"]);
    expect(promptEvents(harness).at(-1)).toEqual({
      channel: ASK_USER_BLOCKED_EVENT,
      payload: { active: false },
    });
  });

  it("blocks secret searches when user cancels", async () => {
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      resultScanning: false,
    });

    const result = await runToolCall(
      harness,
      { toolName: "grep", input: { path: ".", pattern: "password" } },
      createContext(harness.selected, tmpdir(), undefined),
    );

    expect(result).toMatchObject({ block: true });
    expect(promptEvents(harness).at(-1)).toEqual({
      channel: ASK_USER_BLOCKED_EVENT,
      payload: { active: false },
    });
    expect(harness.emitted.filter(({ channel }) => channel === "herdr:blocked").at(-1)).toEqual({
      channel: "herdr:blocked",
      payload: { active: false, label: "Waiting for secret-search approval" },
    });
  });

  it("clears both prompt states when selection UI errors", async () => {
    const harness = createHarness({
      envShield: true,
      scanBashReads: false,
      resultScanning: false,
    });
    const error = new Error("selection failed");

    await expect(
      runToolCall(
        harness,
        { toolName: "bash", input: { command: "env" } },
        createContext(harness.selected, tmpdir(), "Deny", error),
      ),
    ).rejects.toThrow("selection failed");

    expect(promptEvents(harness).at(-1)).toEqual({
      channel: ASK_USER_BLOCKED_EVENT,
      payload: { active: false },
    });
    expect(harness.emitted.filter(({ channel }) => channel === "herdr:blocked").at(-1)).toEqual({
      channel: "herdr:blocked",
      payload: { active: false, label: "Waiting for env exposure approval" },
    });
  });

  it("keeps result redaction registered after enabling scanning at session start", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-config-transition-"));
    const secretPath = join(root, "secret.env");
    const secret = ["AKIA", "1234567890ABCDEF"].join("");
    writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${secret}\n`, "utf8");
    let loadCount = 0;
    const evaluate = vi.fn(async () => ({
      action: "allow" as const,
      reason: "safe_workspace_read",
      candidate: true,
      attempted: true,
      evaluationId: "transition-eval-1",
    }));
    const harness = createHarness(
      {},
      () => {
        loadCount += 1;
        return {
          sentinelCreds: {
            enabled: true,
            envShield: false,
            scanBashReads: false,
            resultScanning: loadCount > 1,
          },
        };
      },
      {
        getPermissionConfig: () => ({ mode: "yolo-auto", yoloAutoMaxLevel: "l1" }),
        yoloAutoEvaluator: { evaluate },
      },
    );

    await harness.handlers.get("session_start")?.[0](
      { reason: "workspace" },
      { cwd: root, hasUI: false },
    );
    expect(harness.handlers.get("tool_result")).toHaveLength(1);

    await runToolCall(
      harness,
      { toolCallId: "transition-read", toolName: "read", input: { path: secretPath } },
      { hasUI: false, cwd: root, ui: { select: vi.fn(), setStatus() {} } },
    );
    const result = await runToolResult(
      harness,
      {
        toolCallId: "transition-read",
        toolName: "read",
        input: { path: secretPath },
        content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
        isError: false,
      },
      { cwd: root },
    );

    expect(result).toEqual({
      content: [{ type: "text", text: "AWS_ACCESS_KEY_ID=[REDACTED: AWS Access Key]" }],
    });
  });

  it("redacts secrets in text result blocks while preserving image blocks", async () => {
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
    });
    const image = { type: "image", data: "aW1hZ2U=", mimeType: "image/png" };
    const secret = "AKIA1234567890ABCDEF";

    const result = await runToolResult(harness, {
      toolCallId: "read-1",
      toolName: "read",
      input: { path: "config.env" },
      content: [
        { type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` },
        image,
        { type: "text", text: `BACKUP_AWS_ACCESS_KEY_ID=${secret}` },
      ],
      isError: false,
    });

    expect(result).toEqual({
      content: [
        { type: "text", text: "AWS_ACCESS_KEY_ID=[REDACTED: AWS Access Key]" },
        image,
        { type: "text", text: "BACKUP_AWS_ACCESS_KEY_ID=[REDACTED: AWS Access Key]" },
      ],
    });
  });

  it("redacts scanned blocks when another text block cannot be scanned", async () => {
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
    });
    const secret = "AKIA1234567890ABCDEF";
    const oversizedText = "x".repeat(1_048_577);

    const result = await runToolResult(harness, {
      toolCallId: "read-mixed",
      toolName: "read",
      input: { path: "mixed-output" },
      content: [
        { type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` },
        { type: "text", text: oversizedText },
      ],
      isError: false,
    });

    expect(result).toEqual({
      content: [
        { type: "text", text: "AWS_ACCESS_KEY_ID=[REDACTED: AWS Access Key]" },
        { type: "text", text: "[sentinel-creds] Output withheld because secret scanning was unavailable." },
      ],
    });
  });

  it("honors raw reveal for persistently whitelisted reads", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-whitelist-"));
    const secretPath = join(root, "secret.env");
    const secret = "AKIA1234567890ABCDEF";
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      allowRawReveal: true,
      readAllowedPaths: [secretPath],
    });

    const result = await runToolResult(harness, {
      toolCallId: "read-whitelisted",
      toolName: "read",
      input: { path: secretPath },
      content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
      isError: false,
    });

    expect(result).toBeUndefined();
  });

  it("uses the workspace false override for raw reveal", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-workspace-"));
    const secretPath = join(root, "secret.env");
    const secret = "AKIA1234567890ABCDEF";
    const harness = createHarness({}, (cwd) => ({
      sentinelCreds: {
        enabled: true,
        envShield: false,
        scanBashReads: false,
        allowRawReveal: cwd !== root,
        readAllowedPaths: cwd === root ? [secretPath] : [],
      },
    }));
    await harness.handlers.get("session_start")?.[0](
      { reason: "startup" },
      { cwd: root, hasUI: false },
    );

    const result = await runToolResult(harness, {
      toolCallId: "read-workspace-false",
      toolName: "read",
      input: { path: secretPath },
      content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
      isError: false,
    }, { cwd: root });

    expect(result).toEqual({
      content: [{ type: "text", text: "AWS_ACCESS_KEY_ID=[REDACTED: AWS Access Key]" }],
    });
  });

  it("uses the workspace true override for raw reveal", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-workspace-"));
    const secretPath = join(root, "secret.env");
    const secret = "AKIA1234567890ABCDEF";
    const harness = createHarness({}, (cwd) => ({
      sentinelCreds: {
        enabled: true,
        envShield: false,
        scanBashReads: false,
        allowRawReveal: cwd === root,
        readAllowedPaths: cwd === root ? [secretPath] : [],
      },
    }));
    await harness.handlers.get("session_start")?.[0](
      { reason: "startup" },
      { cwd: root, hasUI: false },
    );

    const result = await runToolResult(harness, {
      toolCallId: "read-workspace-true",
      toolName: "read",
      input: { path: secretPath },
      content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
      isError: false,
    }, { cwd: root });

    expect(result).toBeUndefined();
  });

  it("uses the session workspace for relative persistent whitelist paths", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-relative-"));
    const secretPath = join(root, "secret.env");
    const secret = "AKIA1234567890ABCDEF";
    const harness = createHarness({}, (cwd) => ({
      sentinelCreds: {
        enabled: true,
        envShield: false,
        scanBashReads: false,
        allowRawReveal: cwd === root,
        readAllowedPaths: cwd === root ? [secretPath] : [],
      },
    }));
    await harness.handlers.get("session_start")?.[0](
      { reason: "startup" },
      { cwd: root, hasUI: false },
    );

    const result = await runToolResult(harness, {
      toolCallId: "read-relative-whitelist",
      toolName: "read",
      input: { path: "secret.env" },
      content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
      isError: false,
    }, { cwd: root });

    expect(result).toBeUndefined();
  });

  it("uses the session workspace for relative one-time raw reveal", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-relative-"));
    const secretPath = join(root, "secret.env");
    const secret = "AKIA1234567890ABCDEF";
    writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${secret}\n`, "utf8");
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      allowRawReveal: true,
    });
    await harness.handlers.get("session_start")?.[0](
      { reason: "startup" },
      { cwd: root, hasUI: false },
    );

    await runToolCall(
      harness,
      { toolCallId: "read-relative-once", toolName: "read", input: { path: "secret.env" } },
      createContext(harness.selected, root, "Allow once"),
    );

    const result = await runToolResult(harness, {
      toolCallId: "read-relative-once",
      toolName: "read",
      input: { path: "secret.env" },
      content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
      isError: false,
    }, { cwd: root });

    expect(result).toBeUndefined();
  });

  it("does not reuse raw-reveal allowance across tool calls for same path", async () => {
    const root = mkdtempSync(join(tmpdir(), "sentinel-result-"));
    const secretPath = join(root, "secret.env");
    const secret = "AKIA1234567890ABCDEF";
    writeFileSync(secretPath, `AWS_ACCESS_KEY_ID=${secret}\n`, "utf8");
    const harness = createHarness({
      envShield: false,
      scanBashReads: false,
      allowRawReveal: true,
    });

    await runToolCall(
      harness,
      { toolCallId: "read-1", toolName: "read", input: { path: secretPath } },
      createContext(harness.selected, root, "Allow once"),
    );

    const result = await runToolResult(harness, {
      toolCallId: "read-2",
      toolName: "read",
      input: { path: secretPath },
      content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
      isError: false,
    });

    expect(result).toEqual({
      content: [{ type: "text", text: "AWS_ACCESS_KEY_ID=[REDACTED: AWS Access Key]" }],
    });

    const matchingResult = await runToolResult(harness, {
      toolCallId: "read-1",
      toolName: "read",
      input: { path: secretPath },
      content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${secret}` }],
      isError: false,
    });

    expect(matchingResult).toBeUndefined();
  });
});
