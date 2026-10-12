# pi-sentinel

Pi extension for permission enforcement, network-domain gating, sandboxed Bash, and masked-path enforcement.

## Install

Install a reviewed tag or commit:

```bash
pi install git:git@github.com:DxTa/pi-sentinel@<reviewed-tag-or-commit>
```

Git is the supported distribution path. No build step is required. The npm name is reserved but not published.

## Security defaults

- Normal workspace-local `read`, `write`, `edit`, `grep`, `find`, and `ls` operations are auto-approved after canonical workspace checks. `.env*` direct reads follow the configured path rules; `.env*` writes and edits remain protected. External paths and symlink escapes still use the existing gates.
- Bash asks by default, except `git status` and `git diff`.
- Recognized literal network destinations not on the allowlist require approval. Domain preflight uses static command extraction; dynamic or obfuscated destinations may not be identified. Host-bypassed commands have normal host network access after Bash approval.
- `yolo-auto` evaluates eligible workspace-local reads, listings, writes, and edits, plus already-sandboxed Bash after normal gates. Deterministic path, network, sandbox, and destructive-action gates remain authoritative.
- Pi clipboard images may be read directly in `manual`, `yolo`, and `yolo-auto` only when they come from an interactive input event and match the current OS temp-root `pi-clipboard-<UUID>.<extension>` shape. Writes, Bash, compound commands, and untracked temp files remain protected.
- SRT is enabled with the network-capable `online-dev` profile.
- **Approved Bash runs on the host by default** because bundled `sandbox.bypassCommands` is `['*']`. Set it to `[]` to require SRT wrapping and fail closed when SRT is unavailable.
- SRT-wrapped commands can reach local Unix sockets by default. This includes Docker, SSH-agent, and database sockets.
- Docker socket access is host-admin equivalent. Treat Docker approval as host access.

## Threat model

**Protects:** user files, configured credential-path masks, command authorization, network egress, sandbox boundaries, and accidental destructive actions.

**Untrusted inputs:** model output, tool arguments, MCP and skill requests, project files, shell commands and output, and external worker responses.

**Enforcement boundary:** deterministic gates run before execution and before `yolo-auto`. SRT denies configured credential-path patterns for wrapped commands; `.env*` reads follow permission/path rules. Non-bypassed Bash is wrapped by SRT; bypassed Bash has normal host filesystem and network access after permission and network preflight. A bypass is not a sandbox.

**Model safety:** `yolo-auto` evaluates eligible ask-state workspace-local read/list/write/edit requests and already-sandboxed Bash. The evaluator sends path/tool metadata for reads and listings, up to 800 characters of write/edit content, or a redacted Bash command. Read output is not sent, so prompt injection inside a file cannot be detected before reading. Sensitive paths, external targets, network operations, unsandboxed Bash, and model failures prompt. Fixed thresholds remain authoritative; 5% of would-allow decisions prompt for audit (20% for allows learned from history).

**Worker trust:** the configured worker and model cache are trusted components. The socket uses owner-only filesystem permissions, but the protocol does not authenticate the peer or prove response honesty.

**Out of scope:** a compromised host, Pi runtime, dependency, SRT, Docker daemon, or external service; actions the user explicitly approves outside SRT; and data exfiltration through an allowed host command or network destination. This extension is not a privilege boundary against a host administrator.

See [`SECURITY.md`](SECURITY.md) for reporting instructions.

## How it works

```text
request -> canonical workspace file check or permission/path/network gates
        -> yolo-auto for eligible local reads/lists/writes/edits and sandboxed Bash
        -> SRT wrapper or approved host bypass
        -> execute or prompt/deny
```

SRT is the only sandbox backend. SRT-wrapped commands can read the repository and working directory, configured binds, standard runtime/system paths, temporary directories, selected home paths such as `~/.config`, `~/.gitconfig`, and `~/.gitignore`, and the pi-sentinel/SRT package roots. The repository and configured writable binds are writable. Known credential paths are masked by patterns, not by complete secret detection; project scripts and tests remain visible inside the repository.

### Commands inside loops and wrappers

Rules, stored approvals, `yolo` ask patterns, the `yolo-auto` history key, the workspace `cd` check, and the model all use the commands that really run, not the text around them.

- **Removed:** loop, `if`, group, and subshell syntax; `VAR=x` prefixes; `env`, `timeout`, `nice`, `time`, `command`, `nohup`, and `exec`.
- **Read:** `xargs CMD`, `find -exec|-execdir|-ok|-okdir CMD`, `bash|sh|zsh|dash -c '<literal>'` (two levels), and `sudo CMD`. A deny rule or ask pattern on the wrapper itself (for example `sudo *`) still applies.
- **`sudo` always prompts.** No rule, stored approval, or `yolo-auto` decision allows it. Classic `yolo` mode still auto-approves it unless an ask pattern matches the inner command.
- **Opaque code never inherits an allow.** This covers `eval`, `source`, `trap`, interpreter `-c`/`-e` (`python`, `node`, `perl`, `ruby`, `php`), `bash` without a script, a `$cmd` command name, `case`, function definitions, a `PATH=`/`LD_*`/`IFS=` prefix, and wrapper options pi-sentinel does not know. Rules cannot allow it, approving it stores nothing, and history cannot convert it. The model can still allow it at the normal thresholds.
- **Model input:** the whole command plus each inner command, each classified alone. A request is allowed only when every input is allowed. More than 8 inner commands, or one longer than 200 bytes, prompts. The byte cap keeps each input inside the model's 256-token window, because a token is never shorter than one byte.
- **History key:** the sorted inner-command patterns, for example `bash:cd *|rm *`. Keys saved earlier age out of the 30-day window.

Approvals saved by earlier versions can contain keyword or wrapper patterns such as `for *`, `do *`, `done`, or `bash *`. They no longer match. List and remove them:

```sh
grep -noE '"(for|while|until|if|then|elif|else|do|done|fi|select|case|esac|bash|sh|zsh|dash|eval|source|xargs|env|timeout|sudo|nohup|time|command|exec|nice)( [^"]*)?"[[:space:]]*:[[:space:]]*"[a-z]+"' ~/.pi/agent/permissions.json .pi/permissions.json
```

## `yolo` mode: hard rules

`yolo` lets requests run without a prompt, including external directories, network `ask` verdicts, and writes outside the workspace, except these hard rules:

- **Denied, no prompt:** `write`, `edit`, and readable Bash commands that write to a forbidden path: `/etc`, `/System`, `/Library`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, `/private/etc`, `/var` (except `/var/folders` and `/var/tmp`), `~/.ssh`, `~/.aws`, and `~/.gnupg`. Symlinks into these paths count, including `link/../etc`. Bash writes are redirects (`>`, `>>`, `&>`) and the verbs `cp`, `mv`, `ln`, `install`, `rm`, `touch`, `mkdir`, `tee`, `truncate`, `chmod`, `chown`, `dd of=`, `sed -i`, `curl -o`, and `wget -O`. Reads are never denied.
- **Prompt:** `rm`, `ssh`, `git push`, and kubectl commands that change a cluster (`apply`, `create`, `delete`, `edit`, `patch`, `replace`, `set`, `scale`, `rollout` except `status`/`history`, `drain`, `cordon`, `uncordon`, `taint`, `label`, `annotate`, `autoscale`, `run`, `expose`, `cp`). Matching uses the executable name and subcommand, so `/bin/rm`, `git -C repo push`, and `kubectl -n prod delete` count while `git log --grep push` does not. Add your own with `yoloAskBashPatterns`.
- **Still protected:** explicit `deny` rules in your config, explicit denied network domains, and `.env*` protection. SRT sandbox grant prompts are unchanged.

Limits:

- The forbidden-path check is best effort. It reads only commands the parser can read, so `eval`, interpreter code (`python -c`), and writer commands not in the list (`tar -C`, `unzip -d`, `git clone <dir>`) pass. The SRT sandbox stays on and is the backstop.
- A `cd` inside a subshell is tracked as if it carried over, so a later relative write in the same command can be denied by mistake.
- `kubectl exec` is not treated as a write.

`manual` and `yolo-auto` are unchanged, including forced prompts for external writes.

## `yolo-auto` worker

In `yolo-auto` mode, pi-sentinel starts or reuses one shared, detached Node worker. The worker uses the Apache-2.0 Lion Warden classifier, pinned to revision `77888f617584758f904faefd6f38d4cf926f6d5d`. The model and tokenizer are not bundled; first startup downloads about 130 MB into `~/.pi/agent/runtime/pi-sentinel/yolo-auto/models`, verifies SHA-256 hashes, and resumes interrupted downloads. The worker fails closed: unavailable or invalid model assets mean permission requests prompt.

The pi-sentinel package is MIT; classifier weights are Apache-2.0. The implementation uses no Python worker and never fetches `l2/` assets.

Override the model directory or Unix socket when needed:

```sh
export PI_SENTINEL_YOLO_AUTO_MODEL_DIR=/path/to/models
export PI_SENTINEL_YOLO_AUTO_SOCKET=/path/to/yolo-auto.sock
```

Each evaluation writes a calibration record to `~/.pi/agent/logs/yolo-auto-calibration.jsonl`. Records contain a hash of classifier input, not raw request text. The owner-only file is mode `0600`, rotates at 50 MB, and retains one `.1` file. A shared active worker can serve multiple Pi sessions; worker failure falls back to prompting.

### Learning from your answers

`yolo-auto` stores one row per evaluation in `~/.pi/agent/extensions/pi-sentinel/decision-store/decisions.db` (mode `0600`): head scores, tool, operation, a coarse pattern key, and a hashed workspace. It stores no prompt or command text. Past answers can turn a model prompt into an allow, or force a prompt:

- **Only your dialog answers are labels.** Failures, timeouts, dismissed dialogs, and auto-approvals write no label. Denials stored within 1 second by earlier versions are ignored.
- **The latest explicit decision for a key in a workspace wins.** A denial prompts until a later approval clears it. Denials in at least two other workspaces also prompt.
- **History may resolve only `threat_benign_low_confidence`.** It never overrides injection, threat, tool-action, sensitive-source, or external-sink findings, or a hard rule. The benign score must be at least 0.5.
- **Project allow:** decayed approvals (14-day half-life) of at least 2.5 over at least 2 days, within 30 days. **Global allow:** the same, across at least 3 workspaces with no denying workspace.
- **Audit approvals add no evidence.** Audit denials count as denials. Telemetry records `fusionVersion`, approval weights, days, and denial counts so any rule can be replayed offline.

Run `node scripts/calibration-report.mjs [calibration.jsonl] [review.jsonl]` to join human approval/denial labels by `evaluationId` and print precision/recall by gate and threshold. It includes the rotated calibration file when present; automatic model approvals are not treated as human labels.

## Commands

| Command | Purpose |
| --- | --- |
| `/sentinel [show\|path\|reset\|help]` | Inspect or reset pi-sentinel configuration. |
| `/domain-gate` | Review network-domain policy and approvals. |
| `/sandbox-status` | Check SRT and sandbox dependencies. |
| `/sandbox-grant path <path> [--ro\|--rw] [--ttl <duration>]` | Grant temporary or persistent filesystem access. |
| `/sandbox-grant network --domain <domain> [--ttl <duration>]` | Grant a sandbox network domain. |
| `/sandbox-revoke <grant-id>` | Revoke a sandbox grant. |

`mode` selects one behavior: `manual` prompts ordinary gated requests, `yolo` enables classic eligible auto-approval, and `yolo-auto` adds model-backed approval for eligible read/list/write/edit and already-sandboxed Bash requests while retaining classic yolo bypass elsewhere. The deterministic canonical workspace file rule applies in every mode. In `yolo` mode, only the hard rules below stop a request; `yolo-auto` keeps its external-path and `.env*` prompts.

## Logs

`permissionReviewLog` defaults to `true` and writes JSONL under `~/.pi/agent/extensions/pi-sentinel/logs/`. Records may include commands, paths, prompt messages, targets, and bounded tool-input previews. `debugLog` is opt-in and records mode, tool/gate metadata, prompt timing and outcome, and `yolo_auto.evaluation` phase/latency/provenance metadata. Debug prompt records use lengths and hashes instead of prompt bodies; neither stream is intended to store write content, model payloads, or secret values. Treat both logs as sensitive; they are not guaranteed to be fully redacted or automatically rotated. Disable logging when it is not required and restrict the agent directory to the owning user.

## Configuration

Bundled defaults live in [`config.json`](config.json). Precedence, lowest to highest:

1. bundled defaults;
2. global `~/.pi/agent/permissions.json`;
3. trusted project `<project>/.pi/permissions.json`;
4. per-agent configuration;
5. security profile overlay.

Use [`schemas/permissions.schema.json`](schemas/permissions.schema.json) for the complete schema. Runtime settings merge from bundled defaults, global `~/.pi/agent/permissions.json`, and trusted project `<project>/.pi/permissions.json`, with project settings highest. Permission rules additionally merge from global/project agent frontmatter and the active security-profile overlay; those layers do not override general runtime settings.

Set `PI_SENTINEL_MODE` to `manual`, `yolo`, or `yolo-auto` to override the effective mode for that process only. It does not change config files or the reported global/project configs. Invalid values are ignored and reported as config issues. Child processes inherit the override unless their environment removes it. Explicitly changing Mode in settings still saves that choice for future processes; the current process continues to use the environment override.

In `/sentinel`, the **Mode scope** row picks where the next Mode change is stored:

- `session`: in memory only, until the next session starts. It overrides `PI_SENTINEL_MODE` and file config.
- `project`: `<project>/.pi/permissions.json`. A committed file changes the mode for everyone who uses the repository.
- `global` (default): `~/.pi/agent/permissions.json`. A project `mode` still overrides it; pi-sentinel warns when that happens.

Choosing `project` or `global` replaces an active session mode.

For stronger Bash isolation:

```json
{
  "sandbox": {
    "bypassCommands": [],
    "defaultProfile": "offline-dev"
  }
}
```

Set `allowDocker: false` in the active sandbox profile when Docker is not required. Keep grants narrow and short-lived.

## Host requirements

- Node.js `>=23.6.0`.
- macOS and Linux: SRT package; Linux also needs `rg`, `bwrap`, and `socat`.
- Windows: SRT is unavailable. Use `bypassCommands: []` to fail closed rather than run Bash outside SRT.

## Development

```bash
npm ci
npm run check
npm test
```

Tests live beside implementation under `src/`. Package-local tests must not require this repository or a parent checkout.

## Service API

Other Pi extensions can query the process-local permission service:

```typescript
import { getPermissionsService } from "@dxta/pi-sentinel";

const service = getPermissionsService();
const result = service?.checkPermission("bash", "git status");
```

Call `getPermissionsService()` per use so `/reload` and extension load order do not leave a stale reference.

## Security release gate

This repository carries a historical hardening patch for `@anthropic-ai/sandbox-runtime@0.0.59` under [`patches/`](patches/). The current 0.0.75 dependency is pinned for macOS profile compaction; macOS npm installs with lifecycle scripts enabled run `bin/patch-sandbox-runtime.mjs` to split oversized SBPL filter sets into bounded rules and spill oversized profile text to private files while retaining every filter. This does not establish equivalence with the historical hardening patch. Do not publish or tag a security release until that equivalence is verified or the install process applies the historical hardening explicitly.

## License

MIT. Original upstream attribution is retained in [`LICENSE`](LICENSE).
