import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { protectedPushReason } from "./yolo-protected-branch";

function git(dir: string, args: string[]): void {
  execFileSync("git", ["-C", dir, ...args], { stdio: "ignore" });
}

describe("protectedPushReason", () => {
  let repo: string;

  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), "sentinel-push-"));
    git(repo, ["init", "-q"]);
    git(repo, ["symbolic-ref", "HEAD", "refs/heads/feature"]);
    git(repo, ["symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk"]);
  });

  afterEach(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  const blocked = (command: string) => expect(protectedPushReason(command, repo, true)).not.toBeNull();
  const allowed = (command: string) => expect(protectedPushReason(command, repo, true)).toBeNull();

  it("allows pushes to a feature branch", () => {
    allowed("git push origin feature");
    allowed("git push");
    allowed("git push -o ci.skip origin feature");
    allowed("git push origin HEAD");
  });

  it("blocks main, master and the remote default branch by name", () => {
    blocked("git push origin main");
    blocked("git push origin master");
    blocked("git push origin trunk");
    blocked("git push origin HEAD:main");
    blocked("git push origin HEAD:refs/heads/main");
    blocked("git push origin feature:main");
    blocked("git push origin :main");
  });

  it("blocks a plain push while the default branch is checked out", () => {
    git(repo, ["symbolic-ref", "HEAD", "refs/heads/main"]);
    blocked("git push");
    blocked("git push origin");
  });

  it("blocks pushes that write every branch", () => {
    blocked("git push --all origin");
    blocked("git push --mirror origin");
  });

  it("blocks a push target it cannot resolve in yolo, but leaves it to the prompt otherwise", () => {
    blocked("git push origin $BRANCH");
    expect(protectedPushReason("git push origin $BRANCH", repo, false)).toBeNull();
  });

  it("finds pushes inside chains and honours -C", () => {
    blocked("cd src && git push origin main");
    blocked(`git -C ${repo} push origin main`);
  });

  it("ignores commands that are not pushes", () => {
    allowed("git log --grep push");
    allowed("git push origin v1.0");
  });
});
