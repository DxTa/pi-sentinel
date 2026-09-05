import { describe, expect, it } from "vitest";

import {
  ASK_USER_BLOCKED_EVENT,
  ASK_USER_PROMPT_EVENT,
  buildPromptPayload,
  createSentinelPrompt,
  formatPromptTitle,
  runPromptLifecycle,
} from "./prompt";

const prompt = createSentinelPrompt({
  header: "Env exposure",
  question: "Allow this command to expose environment variables?",
  details: "The command may print values from the process environment.",
  options: [
    {
      label: "Allow once",
      description: "Run this command once; output remains subject to redaction.",
    },
    {
      label: "Deny",
      description: "Block this command.",
    },
  ],
});

describe("sentinel prompt adapter", () => {
  it("builds structured single-select metadata", () => {
    const payload = buildPromptPayload(prompt);

    expect(payload).toEqual({
      questions: [
        {
          question: "Allow this command to expose environment variables?",
          header: "Env exposure",
          multiSelect: false,
          options: [
            {
              label: "Allow once",
              description: "Run this command once; output remains subject to redaction.",
              hasPreview: false,
            },
            {
              label: "Deny",
              description: "Block this command.",
              hasPreview: false,
            },
          ],
        },
      ],
    });
    expect(JSON.parse(JSON.stringify(payload))).toEqual(payload);
    expect(formatPromptTitle(prompt)).toBe(
      "[sentinel-creds] Env exposure\n\nThe command may print values from the process environment.\n\nAllow this command to expose environment variables?\n\nAllow once — Run this command once; output remains subject to redaction.\nDeny — Block this command.",
    );
  });

  it.each([
    ["header", () => createSentinelPrompt({ ...prompt, header: "12345678901234567" })],
    ["question", () => createSentinelPrompt({ ...prompt, question: "Allow this command" })],
    ["option count", () => createSentinelPrompt({ ...prompt, options: [prompt.options[0]] })],
    ["duplicate labels", () => createSentinelPrompt({ ...prompt, options: [prompt.options[0], prompt.options[0]] })],
    ["empty description", () => createSentinelPrompt({ ...prompt, options: [{ ...prompt.options[0], description: "" }, prompt.options[1]] })],
  ])("rejects invalid %s", (_name, build) => {
    expect(build).toThrow();
  });

  it("sanitizes untrusted prompt details before native rendering", () => {
    const unsafe = createSentinelPrompt({
      ...prompt,
      details: "Pattern \u001b[31mBAD\u001b[0m\u001b]0;spoofed title\u0007\r\nnext\u0000",
    });
    const title = formatPromptTitle(unsafe);

    expect(title).toContain("Pattern BAD");
    expect(title).toContain("next");
    expect(title).not.toMatch(/[\u0000\u001b\u007f\u009b\r]/);

    const long = formatPromptTitle(createSentinelPrompt({
      ...prompt,
      details: "x".repeat(5000),
    }));
    expect(long.length).toBeLessThan(4300);
  });

  it("emits balanced blocked lifecycle around the wait", async () => {
    const events: Array<{ channel: string; payload: unknown }> = [];
    const result = await runPromptLifecycle(
      { emit: (channel, payload) => events.push({ channel, payload }) },
      prompt,
      async () => {
        events.push({ channel: "wait", payload: undefined });
        return "Allow once";
      },
    );

    expect(result).toBe("Allow once");
    expect(events).toEqual([
      { channel: ASK_USER_PROMPT_EVENT, payload: buildPromptPayload(prompt) },
      { channel: ASK_USER_BLOCKED_EVENT, payload: { active: true } },
      { channel: "wait", payload: undefined },
      { channel: ASK_USER_BLOCKED_EVENT, payload: { active: false } },
    ]);
  });

  it("clears blocked state when wait rejects", async () => {
    const events: Array<{ channel: string; payload: unknown }> = [];
    await expect(
      runPromptLifecycle(
        { emit: (channel, payload) => events.push({ channel, payload }) },
        prompt,
        async () => {
          throw new Error("cancelled");
        },
      ),
    ).rejects.toThrow("cancelled");

    expect(events.at(-1)).toEqual({
      channel: ASK_USER_BLOCKED_EVENT,
      payload: { active: false },
    });
  });
});
