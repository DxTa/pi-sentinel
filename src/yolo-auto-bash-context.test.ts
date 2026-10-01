import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { buildYoloAutoBashContext } from "./yolo-auto-bash-context.js";

const workspace = process.cwd();

describe("buildYoloAutoBashContext", () => {
  it("keeps workspace-relative paths and commands eligible", () => {
    const result = buildYoloAutoBashContext("cat src/index.ts", ["src/index.ts"], workspace);

    expect(result).toEqual({ command: "cat src/index.ts", workspaceLocal: true, hardRuleHit: false });
  });

  it("redacts absolute workspace paths to relative paths", () => {
    const absolutePath = join(workspace, "src/index.ts");
    const result = buildYoloAutoBashContext("cat " + absolutePath, [absolutePath], workspace);

    expect(result).toEqual({ command: "cat src/index.ts", workspaceLocal: true, hardRuleHit: false });
    expect(result.command).not.toContain(workspace);
  });

  it("marks sensitive paths as hard rules and redacts them", () => {
    const result = buildYoloAutoBashContext("cat /etc/hosts", ["/etc/hosts"], workspace);

    expect(result).toEqual({ command: "cat <sensitive-path>", workspaceLocal: false, hardRuleHit: true });
    expect(result.command).not.toContain("/etc/hosts");
  });

  it("rejects unclassified absolute paths and redacts them", () => {
    const result = buildYoloAutoBashContext("printf /etc/hosts", [], workspace);

    expect(result).toEqual({ command: "printf <sensitive-path>", workspaceLocal: false, hardRuleHit: true });
  });

  it("rejects dynamic and external path operands", () => {
    const dynamic = buildYoloAutoBashContext("cat $HOME/.ssh/id_rsa", ["$HOME/.ssh/id_rsa"], workspace);
    const external = buildYoloAutoBashContext("cat ../outside.txt", ["../outside.txt"], workspace);

    expect(dynamic).toEqual({ command: "cat <sensitive-path>", workspaceLocal: false, hardRuleHit: true });
    expect(external).toEqual({ command: "cat <external-path>", workspaceLocal: false, hardRuleHit: false });
  });

  it("keeps recognized network targets out of classifier eligibility", () => {
    const result = buildYoloAutoBashContext("curl https://example.com/data", [], workspace);

    expect(result.workspaceLocal).toBe(false);
  });
});
