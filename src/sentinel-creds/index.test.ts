import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

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

function createHarness(overrides: Record<string, unknown> = {}): Harness {
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
    getConfig: () => ({
      sentinelCreds: {
        enabled: true,
        auditLogPath,
        ...overrides,
      },
    }),
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

describe("sentinel-creds structured prompt integration", () => {
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
});
