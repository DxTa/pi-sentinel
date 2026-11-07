# pi-sentinel reference

Detailed behavior, configuration, and security notes. Start with the [README](../README.md).

## How it works

```text
tool call -> workspace file check, permission rules, path / network gates
          -> auto-mode classifier (eligible local reads/lists/writes/edits and sandboxed Bash)
          -> SRT wrapper or approved host bypass
          -> run, prompt, or deny
```

Deterministic gates always run first. The classifier can only turn a prompt into an allow for eligible requests; it never overrides a deny.

SRT is the only sandbox backend. SRT-wrapped commands can read the repository and working directory, configured binds, standard runtime/system paths, temporary directories, selected home paths such as `~/.config`, `~/.gitconfig`, and `~/.gitignore`, and the pi-sentinel/SRT package roots. The repository and configured writable binds are writable. Known credential paths are masked by patterns, not by complete secret detection; project scripts and tests remain visible inside the repository.

## Commands inside loops and wrappers

Rules, stored approvals, `yolo` ask patterns, the `auto` history key, the workspace `cd` check, and the model all use the commands that really run, not the text around them.

- **Removed:** loop, `if`, group, and subshell syntax; `VAR=x` prefixes; `env`, `timeout`, `nice`, `time`, `command`, `nohup`, and `exec`.
- **Read:** `xargs CMD`, `find -exec|-execdir|-ok|-okdir CMD`, `bash|sh|zsh|dash -c '<literal>'` (two levels), and `sudo CMD`. A deny rule or ask pattern on the wrapper itself (for example `sudo *`) still applies.
- **`sudo` always prompts.** No rule, stored approval, or `auto` decision allows it. Classic `yolo` mode still auto-approves it unless an ask pattern matches the inner command.
- **Opaque code never inherits an allow.** This covers `eval`, `source`, `trap`, interpreter `-c`/`-e` (`python`, `node`, `perl`, `ruby`, `php`), `bash` without a script, a `$cmd` command name, `case`, function definitions, a `PATH=`/`LD_*`/`IFS=` prefix, and wrapper options pi-sentinel does not know. Rules cannot allow it, approving it stores nothing, and history cannot convert it. The model can still allow it at the normal thresholds.
- **Model input:** the whole command plus each inner command, each classified alone. A request is allowed only when every input is allowed. More than 8 inner commands, or one longer than 200 bytes, prompts. The byte cap keeps each input inside the model's 256-token window, because a token is never shorter than one byte.
- **History key:** the sorted inner-command patterns, for example `bash:cd *|rm *`. Keys saved earlier age out of the 30-day window.

Approvals saved by earlier versions can contain keyword or wrapper patterns such as `for *`, `do *`, `done`, or `bash *`. They no longer match. List and remove them:

```sh
grep -noE '"(for|while|until|if|then|elif|else|do|done|fi|select|case|esac|bash|sh|zsh|dash|eval|source|xargs|env|timeout|sudo|nohup|time|command|exec|nice)( [^"]*)?"[[:space:]]*:[[:space:]]*"[a-z]+"' ~/.pi/agent/permissions.json .pi/permissions.json
```

## `yolo` mode: hard rules

`yolo` never opens a dialog. Every request resolves to allow or block-with-reason, so unattended runs do not stall.

- **Allowed:** workspace requests, pathless tools, network `ask` verdicts, non-sensitive external reads, and `.env` searches (`grep`, `find`, `ls`), whose output is redacted.
- **Classifier:** external writes, edits, and Bash go to the [classifier](#auto-mode-classifier). Only a `threat_not_benign` or `injection_detected` result blocks, and only when an operand is outside the workspace or the command has a network target. Commands whose operands all stay in the workspace run whatever the verdict (`npm install` and token-handling code often score as threats); the SRT sandbox bounds them. Any other result, including an unavailable classifier, allows the call.
- **Blocked, no dialog:** these never reach the model.
  - Writes to a forbidden path: `/etc`, `/System`, `/Library`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, `/private/etc`, `/var` (except `/var/folders` and `/var/tmp`), `~/.ssh`, `~/.aws`, `~/.gnupg`. Symlinks into these paths count, including `link/../etc`. Bash writes are redirects (`>`, `>>`, `&>`) and the verbs `cp`, `mv`, `ln`, `install`, `rm`, `touch`, `mkdir`, `tee`, `truncate`, `chmod`, `chown`, `dd of=`, `sed -i`, `curl -o`, and `wget -O`. Reads are never denied.
  - `ssh`, `git push` (other than a plain push), `npm`/`pnpm`/`yarn` `publish`, and kubectl commands that change a cluster (`apply`, `create`, `delete`, `edit`, `patch`, `replace`, `set`, `scale`, `rollout` except `status`/`history`, `drain`, `cordon`, `uncordon`, `taint`, `label`, `annotate`, `autoscale`, `run`, `expose`, `cp`). Matching uses the executable name and subcommand, so `/bin/rm` and `git -C repo push` count while `git log --grep push` does not. Add your own with `yoloAskBashPatterns`. `rm` is allowed when every operand stays in the workspace, no hard rule hits, and nothing else in the command is on this list; any other `rm` blocks.
  - Sensitive external reads, and any explicit `deny` rule: a policy deny stays a deny, with no override dialog.
  - Explicitly denied network domains and sandbox auth-exception `deny` rules.
- **Sandbox requests:** network and plain path grants are given once; folders the masked-file scan cannot check are granted for the session. Credential and masked-auth access, unsandboxed execution, and protected writes are denied. When the sandbox denies a file operation in a command whose operands all stay in the workspace (no network target, no hard rule), the agent is told to call it again and yolo reruns that exact command on the host once, so `npm install` and `.git/config` writes work; other host runs are denied.
- **Extension permission requests** (`permissions:rpc:prompt`) are approved automatically.

Every yolo block and sandbox decision is written to the review log, and every review entry records the `mode`.

Limits:

- The forbidden-path check is best effort. It reads only commands the parser can read, so `eval`, interpreter code (`python -c`), and writer commands not in the list (`tar -C`, `unzip -d`, `git clone <dir>`) pass. The SRT sandbox stays on and is the backstop.
- A `cd` inside a subshell is tracked as if it carried over, so a later relative write in the same command can be denied by mistake.
- `kubectl exec` is not treated as a write.
- With the classifier unavailable, external writes and Bash run unchecked except for the hard rules.

`manual` is unchanged. `auto` also sends hard-rule commands to the classifier; see below.

## Egress scan

Before `bash`, `web_fetch`, and MCP tool calls run, the egress scan checks the URLs, headers, and data they send. It runs in every mode and blocks with a reason when it finds:

- a host in `deniedDomains`;
- a host on the bundled exfiltration list (paste, tunnel, request-catcher, and OAST services; `src/network/exfil-domains.ts`);
- a host on the URLhaus threat feed, downloaded at session start, cached in `~/.pi/agent/extensions/pi-sentinel/threat-feed.txt`, and refreshed every 24 hours (a failed download uses the stale cache);
- a raw public IP address or a punycode (`xn--`) host;
- a known secret pattern in the request, sent to a host that is not in `allowedDomains`.

The scan reads text only. It cannot see encoded data, DNS tunnels, or an upload done inside a script file.

## `auto` mode classifier

pi-sentinel starts or reuses one shared, detached Node worker. It runs the Apache-2.0 Lion Warden classifier, pinned to revision `77888f617584758f904faefd6f38d4cf926f6d5d`. The model and tokenizer are not bundled; first startup downloads about 320 MB (the FP16 build; profile `lion-warden-fp16`) into `~/.pi/agent/runtime/pi-sentinel/auto-mode/models`, verifies SHA-256 hashes, and resumes interrupted downloads. The worker fails closed: unavailable or invalid model assets mean permission requests prompt. No Python is required.

What the classifier sees: path/tool metadata for reads and listings, up to 800 characters of write/edit content, a redacted Bash command, or the tool name and arguments of an MCP call (calls whose arguments exceed 800 characters prompt). An MCP call is allowed only when the model reads it as a read or list and every other check passes. Read output is not sent, so prompt injection inside a file cannot be detected before reading. Only your own `allow` rules (global, project, session) skip the model; builtin and bundled defaults go to it like an ask. Workspace reads and listings need no model. External targets, network operations, and non-workspace Bash are judged by the model and may be approved. Sensitive paths and model failures prompt: system roots, `~/Library`, credential folders (`~/.ssh`, `~/.aws`, `~/.gnupg`), shell startup files, and `.env*` selectors. Thresholds come from the model profile, per operation, and are set with `npm run calibrate -- --profile <id> --write` (it refuses to write when the holdout split lets a should-prompt case through). Thresholds are authoritative; 5% of would-allow decisions prompt anyway for audit (20% for allows learned from history).

These checks run before the model and always prompt in `auto`, whatever the model returns. Commands that match a `yolo` hard rule or `yoloAskBashPatterns` (`rm`, `ssh`, `git push`, publish, cluster changes) are not in this list: in `auto` the model judges them. The checks can only add prompts:

- Writes under `.pi/` (permission and settings files), which could widen the rules.
- Writes and edits to agent instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.cursor/rules/`).
- Write and edit content that tells an AI agent to drop its instructions or permission checks, references a secret-named variable (`$GITHUB_TOKEN`, `process.env.NPM_TOKEN`), dumps the environment, or reads a home credential folder. The whole content is checked, not only the 800 characters the model sees.
- MCP tools whose server sets `destructiveHint`, and MCP arguments that hold a SQL write or schema change.

Known gaps: these checks match keywords and phrases, so reworded text can reach the model. Logic changes, such as an edit that makes an auth check return `true`, look benign to both the checks and the model. Treat `auto` as fewer prompts for routine work, not as code review.

Calibration (`scripts/calibration-baseline-fp16.txt`, 181 synthetic cases) allows no should-prompt case for the default FP16 profile. It allows 68% of safe writes, 64% of safe edits, 56% of safe Bash commands, and 46% of safe MCP calls; the rest prompt.

Override the model directory or Unix socket when needed:

```sh
export PI_SENTINEL_AUTO_MODEL_DIR=/path/to/models
export PI_SENTINEL_AUTO_SOCKET=/path/to/auto-mode.sock
```

Each evaluation writes a calibration record to `~/.pi/agent/logs/auto-mode-calibration.jsonl`. Records contain a hash of classifier input, not raw request text. The owner-only file is mode `0600`, rotates at 50 MB, and retains one `.1` file. One worker can serve multiple Pi sessions.

### Learning from your answers

`auto` stores one row per evaluation in `~/.pi/agent/extensions/pi-sentinel/decision-store/decisions.db` (mode `0600`): head scores, tool, operation, a coarse pattern key, and a hashed workspace. It stores no prompt or command text. Past answers can turn a model prompt into an allow, or force a prompt:

- **Only your dialog answers are labels.** Failures, timeouts, dismissed dialogs, and auto-approvals write no label. Denials stored within 1 second by earlier versions are ignored.
- **The latest explicit decision for a key in a workspace wins.** A denial prompts until a later approval clears it. Denials in at least two other workspaces also prompt.
- **History may resolve only `threat_benign_low_confidence`.** It never overrides injection, threat, tool-action, sensitive-source, or external-sink findings, or a hard rule. The benign score must be at least 0.5.
- **Project allow:** decayed approvals (14-day half-life) of at least 2.5 over at least 2 days, within 30 days. **Global allow:** the same, across at least 3 workspaces with no denying workspace.
- **Audit approvals add no evidence.** Audit denials count as denials. Telemetry records `fusionVersion`, approval weights, days, and denial counts so any rule can be replayed offline.

Run `node scripts/calibration-report.mjs [calibration.jsonl] [review.jsonl]` to join human approval/denial labels by `evaluationId` and print precision/recall by gate and threshold. It includes the rotated calibration file when present; automatic model approvals are not treated as human labels.

## Configuration precedence

Bundled defaults live in [`config.json`](../config.json); the full schema is [`schemas/permissions.schema.json`](../schemas/permissions.schema.json). Lowest to highest:

1. bundled defaults;
2. global `~/.pi/agent/permissions.json`;
3. trusted project `<project>/.pi/permissions.json`;
4. per-agent configuration (agent frontmatter);
5. security profile overlay.

MCP tools named `mcp__<server>__<tool>` match `permission.mcp` patterns as `server_tool`, `server:tool`, then `server`, so `"mcp": { "github_*": "allow", "github_delete_*": "deny" }` covers the `github` server. A rule on the full tool name (`"mcp__github__get_issue": "deny"`) wins. Bundled `mcp` defaults do not apply to these tools; unmatched calls use the universal `"*"` rule.

Runtime settings (mode, logs, network, sandbox) merge from layers 1–3. Permission rules also merge from agent frontmatter and the active security-profile overlay; those layers do not override runtime settings.

`PI_SENTINEL_MODE` overrides the mode for that process only. It does not change config files. Invalid values are ignored and reported as config issues. Child processes inherit it unless their environment removes it.

In `/sentinel`, every row shows its effective value and the scope it comes from, for example `manual (project)` or `on (default)`. Changing the mode saves it where the current mode is set, so the change always takes effect:

| Mode currently set by | Change saves to |
| --- | --- |
| session | session (memory, until the session ends) |
| `PI_SENTINEL_MODE` | session, the only layer above it |
| project or legacy project file | `<project>/.pi/permissions.json` (or the legacy file in use) |
| global, legacy global, or default | `~/.pi/agent/permissions.json` |

To store the mode somewhere else, press Enter on the Mode row: the picker lists every mode for the scope where it is set now, plus session and project overrides. It only offers scopes where the change takes effect, so for example it hides global while a project sets the mode. The same is available as `/sentinel mode <manual|yolo|auto> [session|project|global]`, with autocomplete for the mode and scope; the command can also save to a scope that a higher layer hides, and warns when it does. A committed project file changes the mode for everyone who uses the repository. Saving to `project` or `global` replaces an active session mode.

The header shows the mode chain on one line (session, `PI_SENTINEL_MODE`, project, legacy project files, global, legacy global, default) with `▶` on the layer in effect. Logs and sandbox settings always write to the global file; when a project file overrides one of them, its row says so and saving warns that the project value still applies.

## Logs

`permissionReviewLog` (default `true`) writes JSONL under `~/.pi/agent/extensions/pi-sentinel/logs/`. Records may include commands, paths, prompt messages, targets, and bounded tool-input previews. `debugLog` (opt-in) records mode, tool/gate metadata, prompt timing and outcome, and `auto_mode.evaluation` phase/latency/provenance metadata, using lengths and hashes instead of prompt bodies. Neither stream is meant to store write content, model payloads, or secret values, but they are not guaranteed to be fully redacted or rotated. Treat both as sensitive, and disable them when not needed.

## Threat model

**Protects:** user files, configured credential-path masks, command authorization, network egress, sandbox boundaries, and accidental destructive actions.

**Untrusted inputs:** model output, tool arguments, MCP and skill requests, project files, shell commands and output, and classifier worker responses.

**Enforcement boundary:** deterministic gates run before execution and before `auto`. SRT denies configured credential-path patterns for wrapped commands. Workspace-local `.env*` files (except `.env.example`) and recognized home credential/config files can be consumed by sandboxed Bash through per-path read-only SRT grants. Matching bundled dotenv denies are bypassed only for those canonical targets; explicit `ask`/`deny` rules and unrelated restrictions remain enforced. Dotenv output masks comments and literal values of at least six characters; generic credential output is fully redacted. Transformed or encoded values may evade dotenv value matching, and an authorized consumer can still transmit or transform a secret subject to the sandbox network policy. Unsandboxed and bypassed Bash cannot use these automatic grants. A bypass is not a sandbox.

**Worker trust:** the configured worker and model cache are trusted components. The socket uses owner-only filesystem permissions, but the protocol does not authenticate the peer or prove response honesty.

**Out of scope:** a compromised host, Pi runtime, dependency, SRT, Docker daemon, or external service; actions you explicitly approve outside SRT; and data exfiltration through an allowed host command or network destination. This extension is not a privilege boundary against a host administrator.

See [`SECURITY.md`](../SECURITY.md) for the full policy and how to report a vulnerability.

## Linux sandbox setup

SRT runs Bash inside [bubblewrap](https://github.com/containers/bubblewrap), which needs unprivileged user namespaces. Ubuntu 24.04+ blocks these by default through AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`), so `bwrap` fails with `setting up uid map: Permission denied` until it is allowed.

`/sandbox-status` runs a short `bwrap` test and, when this restriction is the cause, prints an AppArmor profile that allows user namespaces for the `bwrap` binary only:

```bash
sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

Any program can then use `bwrap` to create a user namespace, which is the reason Ubuntu added the restriction. That is narrower than the alternative, `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`, which lifts the restriction for every program. Use the sysctl only if the profile does not work on your system.

`rg` is bundled through `@vscode/ripgrep`; SRT uses it to find files to write-protect. Without a prebuilt binary for your platform, pi-sentinel falls back to `rg` on `PATH`.

## Platform support

- macOS and Linux: supported. Linux needs `bwrap` and `socat` (see [Linux sandbox setup](#linux-sandbox-setup)). macOS needs nothing extra.
- `auto` mode needs a prebuilt ONNX Runtime: Linux x64/arm64, macOS on Apple silicon (arm64), and Windows x64/arm64. Intel Macs have none, so use `manual` or `yolo` there; `auto` falls back to prompting.
- Windows: SRT is unavailable. Set `sandbox.bypassCommands: []` so Bash fails closed instead of running unsandboxed.

## Service API

Other Pi extensions can query the process-local permission service:

```typescript
import { getPermissionsService } from "@dxta/pi-sentinel";

const service = getPermissionsService();
const result = service?.checkPermission("bash", "git status");
```

Call `getPermissionsService()` per use so `/reload` and extension load order do not leave a stale reference.

## Security release gate

This repository carries a historical hardening patch for `@anthropic-ai/sandbox-runtime@0.0.59` under [`patches/`](../patches/). The current 0.0.75 dependency is pinned for macOS profile compaction; macOS npm installs with lifecycle scripts enabled run `bin/patch-sandbox-runtime.mjs` to split oversized SBPL filter sets into bounded rules and spill oversized profile text to private files while retaining every filter. This does not establish equivalence with the historical hardening patch. Do not publish or tag a security release until that equivalence is verified or the install process applies the historical hardening explicitly.

