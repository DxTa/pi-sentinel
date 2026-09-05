import { describe, expect, it } from "vitest";

import { checkEnvExposure } from "./env-shield";

const noSafePrefixes: string[] = [];

describe("checkEnvExposure", () => {
  it.each([
    ["python -m pytest .venv/bin/python", ".venv paths are not environment access"],
    ["set -o pipefail", "shell options are not environment dumps"],
    ["set --", "positional-parameter reset is not an environment dump"],
    ["docker export container image.tar", "container export is not shell export listing"],
    ["export FOO=value", "variable assignment is not export listing"],
    ["export FOO", "exporting a named variable is not export listing"],
    ["declare -x FOO=value", "declaring a named exported variable is not export listing"],
    ["env NODE_ENV=test npm test", "env launching a command is not an environment dump"],
    ["env FOO=\"a b\" npm test", "quoted env assignment before a command is not a dump"],
    ["node -e 'console.log(\"env\")'", "quoted env text is not environment access"],
  ])("does not flag %s because %s", (command) => {
    expect(checkEnvExposure(command, noSafePrefixes)).toBeNull();
  });

  it.each([
    ["env", "bare env lists the environment"],
    ["env -0", "null-delimited env lists the environment"],
    ["env --", "end-of-options env lists the environment"],
    ["env FOO=\"a b\"", "quoted env assignments still list the environment"],
    ["env 2>/dev/null", "redirected env still lists the environment"],
    ["env NODE_ENV=test", "env assignments without a command still list the environment"],
    ["/usr/bin/env", "path-qualified env lists the environment"],
    ["(env)", "subshell env lists the environment"],
    ["echo \"$(env)\"", "command-substitution env lists the environment"],
    ["command env", "command-prefixed env lists the environment"],
    ["printenv", "bare printenv lists the environment"],
    ["printenv PATH", "printenv can expose a selected variable"],
    ["set", "bare set lists shell variables"],
    ["set | grep PATH", "set pipeline exposes shell variables"],
    ["export", "bare export lists exported variables"],
    ["export -p", "export -p lists exported variables"],
    ["export --", "export -- lists exported variables"],
    ["declare -xp", "combined declare export-print flags list variables"],
    ["declare -x -p", "separate declare export-print flags list variables"],
    ["export > /tmp/exported", "redirected export lists exported variables"],
    ["set > /tmp/set-vars", "redirected set lists shell variables"],
    ["set 2>/dev/null", "redirected set lists shell variables"],
    ["builtin export", "builtin export lists exported variables"],
    ["env | grep -v '^PATH_'", "inverted safe-prefix filters expose the environment"],
    ["  export", "indented export still lists exported variables"],
    ["echo ok\nset", "multiline shell commands still lists shell variables"],
    ["(export)", "subshell export still lists exported variables"],
    ["then export", "keyword-prefixed export still lists exported variables"],
    ["python -c 'print(os.environ)'", "Python environment object access"],
    ["node -e 'console.log(process.env)'", "Node environment object access"],
    ["node -e 'console.log(process[\"env\"])'", "Bracketed Node environment object access"],
    ["ruby -e 'puts ENV'", "Ruby environment object access"],
    ["printf '%s' \"$API_TOKEN\"", "secret variable expansion"],
  ])("flags %s because %s", (command) => {
    expect(checkEnvExposure(command, noSafePrefixes)).not.toBeNull();
  });

  it("allows only anchored, non-inverted safe env pipelines", () => {
    expect(checkEnvExposure("env | grep '^PATH_'", ["PATH_"])).toBeNull();
    expect(checkEnvExposure("env | grep PATH_", ["PATH_"])).not.toBeNull();
    expect(checkEnvExposure("env | grep -v '^PATH_'", ["PATH_"])).not.toBeNull();
  });
});
