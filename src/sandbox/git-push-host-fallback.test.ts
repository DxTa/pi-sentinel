import { describe, expect, it } from "vitest";

import { literalGitPushKey } from "./git-push-host-fallback";

describe("literalGitPushKey", () => {
  it.each([
    "git push origin main",
    "git -C . push origin main",
    "/usr/bin/git push origin main",
    "'git' 'push' 'origin' 'main'",
  ])("accepts a direct literal push: %s", (command) => {
    expect(literalGitPushKey(command, "/repo")).toBe(JSON.stringify(["/repo", command]));
  });

  it.each([
    "git push origin main && curl https://example.test",
    "git push origin main; echo done",
    "git push origin main\necho done",
    "git push origin main | cat",
    "git push origin main &",
    "git push origin main > /tmp/out",
    "git push origin main 2>&1",
    "git push origin $BRANCH",
    'git push origin "$BRANCH"',
    "git push origin $(cat branch)",
    "git push origin *",
    "bash -c 'git push origin main'",
    "env git push origin main",
    "ssh example.test",
    "git fetch origin main",
    "git pull origin main",
    "echo git push origin main",
    "git push origin main # comment",
  ])("rejects indirect, dynamic or non-push commands: %s", (command) => {
    expect(literalGitPushKey(command, "/repo")).toBeUndefined();
  });

  it("does not normalize command text or share keys across working directories", () => {
    const key = literalGitPushKey("git push origin main", "/repo");
    expect(literalGitPushKey("git  push origin main", "/repo")).not.toBe(key);
    expect(literalGitPushKey("git push origin main", "/other")).not.toBe(key);
  });
});
