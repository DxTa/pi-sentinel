import { describe, expect, it } from "vitest";

import { scanQuotes, splitBashSegments } from "./bash-segments";

const PIPELINE = 'cd src && grep -rn -E "gpt-6-sol|sonnet-5" . | grep -v "sonnet-5\\.5" | head -50; echo; grep -rln -E "gpt-6-sol|sonnet-5([^.]|$)" . | wc -l';

describe("splitBashSegments", () => {
  it("splits only on unquoted control operators", () => {
    expect(splitBashSegments(PIPELINE)).toEqual(['cd src', 'grep -rn -E "gpt-6-sol|sonnet-5" .', 'grep -v "sonnet-5\\.5"', 'head -50', 'echo', 'grep -rln -E "gpt-6-sol|sonnet-5([^.]|$)" .', 'wc -l']);
  });

  it("rejects substitutions outside single quotes and unbalanced quotes", () => {
    expect(splitBashSegments('echo "$(id)"')).toBeNull();
    expect(splitBashSegments('echo `id`')).toBeNull();
    expect(splitBashSegments('cat <(ls)')).toBeNull();
    expect(splitBashSegments('echo \'x')).toBeNull();
    expect(splitBashSegments('echo \'$(id) | x\'')).toEqual(['echo \'$(id) | x\'']);
  });
});

describe("scanQuotes", () => {
  it("masks quoted text without changing length and flags double-quoted expansions", () => {
    const scan = scanQuotes('grep "a|b" \'c;d\' x');
    expect(scan?.masked).toHaveLength(18);
    expect(scan?.masked.includes("|") || scan?.masked.includes(";")).toBe(false);
    expect(scan?.expands).toBe(false);
    expect(scanQuotes('cat "$CONF/x"')?.expands).toBe(true);
    expect(scanQuotes('grep "a([^.]|$)" f')?.expands).toBe(false);
  });
});
