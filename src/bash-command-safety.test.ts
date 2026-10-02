import { describe, expect, it } from "vitest";
import { isReadOnlyBashChain, isReadOnlyBashCommand, isReadOnlyBashDiagnostic } from "./bash-command-safety";

describe("isReadOnlyBashCommand", () => {
  it.each(["ls -la src", "grep TODO src/index.ts", "find src -name '*.ts'", "docker ps"]) (
    "accepts read-only command %s", (command) => expect(isReadOnlyBashCommand(command)).toBe(true),
  );
  it.each(["find . -exec rm -rf {} \;", "sort -o out", "cat secret && touch x", "ls > out", "python script.py", "cat $HOME/.ssh/id_rsa", "grep TODO src/*.ts", "find -L src -name '*.ts'", "less +!touch x file", "more +!touch x file", "sort --compress-program=sh input"]) (
    "rejects unsafe or mutating command %s", (command) => expect(isReadOnlyBashCommand(command)).toBe(false),
  );
});

describe("isReadOnlyBashDiagnostic", () => {
  it.each([
    "docker ps",
    "docker port api 8501",
    "docker inspect --format '{{.State.Status}}' api",
    "orb --help",
    "orbctl --help",
    "ipconfig getifaddr en0",
  ])("accepts safe diagnostic %s", (command) => expect(isReadOnlyBashDiagnostic(command)).toBe(true));
  it.each([
    "docker inspect api",
    "docker inspect --format '{{.Config.Env}}' api",
    "docker ps && rm -rf .",
    "curl https://example.com",
    "ipconfig set en0 DHCP",
  ])("rejects unsafe diagnostic %s", (command) => expect(isReadOnlyBashDiagnostic(command)).toBe(false));
});

describe("isReadOnlyBashChain", () => {
  const cwd = process.cwd();
  it.each([
    "cd src && ls handlers && head -40 index.ts",
    "cd src 2>/dev/null && ls && git log --oneline -5 && cat index.ts | head -60",
    "cd src; grep -n TODO index.ts | head; sed -n 1,12p index.ts",
    "git status && git diff --stat",
    "wc -l src/index.ts 2>&1",
  ])("accepts read-only chain %s", (command) => expect(isReadOnlyBashChain(command, cwd)).toBe(true));
  it.each([
    "cd .. && cat secrets",
    "cd && cat x",
    "cd - && ls",
    "cd ~ && ls",
    "cd src && rm -rf x",
    "cd src && ls > out",
    "cd src && cat $(echo x)",
    "sed -i s,a,b, index.ts",
    "sed -n 1w out index.ts",
    "git push",
    "git diff --output=x",
    "cd src && python3 x.py",
  ])("rejects %s", (command) => expect(isReadOnlyBashChain(command, cwd)).toBe(false));
});
