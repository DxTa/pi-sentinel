import { describe, expect, it } from "vitest";

import { bashInnerCommands, scanQuotes, splitBashSegments } from "./bash-segments";

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

const plain = (commands: string[]) => expect.objectContaining({ commands, opaque: false, elevated: false });

describe("bashInnerCommands: shell syntax and transparent wrappers", () => {
  it.each([
    ["for f in a b; do rm $f; done", ["rm $f"]],
    ["if test -f x; then rm x; else echo no; fi", ["test -f x", "rm x", "echo no"]],
    ["while read l; do echo $l; done", ["read l", "echo $l"]],
    ["for d in a; do { cd ..; }; done", ["cd .."]],
    ["(cd .. && rm x)", ["cd ..", "rm x"]],
    ["! grep x f", ["grep x f"]],
    ["FOO=1 BAR=2 npm test", ["npm test"]],
    ["env FOO=1 rm x", ["rm x"]],
    ["timeout 5 rm x", ["rm x"]],
    ["nice -n 5 rm x", ["rm x"]],
    ["time nohup exec rm x", ["rm x"]],
    ["command rm x", ["rm x"]],
    ["/usr/bin/env FOO=1 rm x", ["rm x"]],
    ["command -v git", ["command -v git"]],
    ["ls -la src", ["ls -la src"]],
  ])("unwraps %s", (command, commands) => {
    expect(bashInnerCommands(command)).toEqual(plain(commands));
  });

  it("returns null where the command cannot be split", () => {
    expect(bashInnerCommands('echo "$(id)"')).toBeNull();
    expect(bashInnerCommands("echo 'x")).toBeNull();
    expect(bashInnerCommands("sleep 1 &")).toBeNull();
  });
});

describe("bashInnerCommands: readable wrappers", () => {
  it.each([
    ["ls | xargs rm -rf", ["ls", "rm -rf"]],
    ["xargs -n 1 -P4 rm", ["rm"]],
    ["xargs -0 -I {} rm {}", ["rm {}"]],
    ["xargs sh -c 'rm \"$1\"' _", ['rm "$1"']],
    ["find . -name x -exec rm {} +", ["find . -name x -exec rm {} +", "rm {}"]],
    ["find . -exec rm {} ';' -exec chmod 600 {} ';'", ["find . -exec rm {} ';' -exec chmod 600 {} ';'", "rm {}", "chmod 600 {}"]],
    ["bash -c 'cd src && rm -rf build'", ["cd src", "rm -rf build"]],
    ['sh -c "echo hi"', ["echo hi"]],
    ["bash -lc 'ls'", ["ls"]],
    ["bash -c \"sh -c 'rm x'\"", ["rm x"]],
    ["bash -o pipefail -c 'rm x'", ["rm x"]],
    ["bash script.sh", ["bash script.sh"]],
    ["bash -x script.sh -c", ["bash -x script.sh -c"]],
  ])("extracts %s", (command, commands) => {
    expect(bashInnerCommands(command)).toEqual(plain(commands));
  });

  it("marks sudo commands as elevated and returns the command it runs", () => {
    expect(bashInnerCommands("sudo rm -rf /tmp/x")).toMatchObject({ commands: ["rm -rf /tmp/x"], opaque: false, elevated: true });
    expect(bashInnerCommands("sudo -u root env FOO=1 rm x")).toMatchObject({ commands: ["rm x"], opaque: false, elevated: true });
  });
});

describe("bashInnerCommands: code that cannot be read", () => {
  it.each([
    ['eval "$cmd"'],
    ["eval rm x"],
    ["source env.sh"],
    [". env.sh"],
    ["trap 'rm x' EXIT"],
    ["python3 -c 'import os'"],
    ['node -e "1"'],
    ["perl -pi -e 's/a/b/' f"],
    ["bash"],
    ["bash -s arg"],
    ["bash < script.sh"],
    ["bash <<EOF\nrm x\nEOF"],
    ['bash -c "$x"'],
    ["bash -c"],
    ["$cmd arg"],
    ["${CMD} x"],
    ["case $x in a) rm x;; esac"],
    ["f() { rm x; }"],
    ["find . -exec rm {}"],
    ["bash -c 'eval $x'"],
    ["bash -c \"bash -c 'sh -c ls'\""],
    ["xargs --arg-file=x rm"],
    ["env -S 'rm x'"],
    ["timeout --signal=KILL 5 rm x"],
    ["PATH=/tmp/evil ls"],
    ["LD_PRELOAD=x.so ls"],
    ["exec > out.log"],
    ["'eval' x"],
    ['"sudo" rm x'],
    ['e"v"al x'],
    ["'bash' -c 'rm x'"],
    ["'rm' x"],
    ["builtin eval x"],
    ["bash '-c' 'rm x'"],
    ["bash -c '\"eval\" rm x'"],
    ["bash -c '\"sudo\" rm x'"],
  ])("marks %s opaque and keeps it visible to deny rules", (command) => {
    const inner = bashInnerCommands(command);
    expect(inner?.opaque).toBe(true);
    expect(inner?.commands.length).toBeGreaterThan(0);
  });

  it("keeps the other commands of an opaque chain", () => {
    expect(bashInnerCommands('ls && eval "$x"')).toMatchObject({ commands: ["ls", 'eval "$x"'], opaque: true, elevated: false });
    expect(bashInnerCommands("cat a | sh")).toMatchObject({ commands: ["cat a", "sh"], opaque: true, elevated: false });
  });

  it("returns null for escaped terminators that the splitter rejects", () => {
    expect(bashInnerCommands("find . -exec rm {} \\;")).toBeNull();
  });

  it("combines elevated and readable inner code", () => {
    expect(bashInnerCommands("sudo bash -c 'rm x'")).toMatchObject({ commands: ["rm x"], opaque: false, elevated: true });
  });
});

describe("bashInnerCommands: scope", () => {
  it.each([
    ["(cd src && ls)", true],
    ["bash -c 'cd src'", true],
    ["ls | xargs sh -c 'cd x'", true],
    ["find . -exec cd x {} +", true],
    ["cd src && ls", false],
    ["for d in a; do cd src; done", false],
  ])("marks %s scoped=%s", (command, scoped) => {
    expect(bashInnerCommands(command)?.scoped).toBe(scoped);
  });
});
