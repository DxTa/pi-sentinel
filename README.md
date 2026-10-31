# pi-sentinel

A security extension for the [Pi coding agent](https://github.com/earendil-works/pi). It sits between the agent and your machine and decides, for every tool call, whether to allow it, prompt you, or block it.

- **Permission rules** for `read`, `write`, `edit`, `bash`, MCP tools, and skills.
- **Network domain gate**: prompts before Bash reaches a domain you have not allowed.
- **Sandboxed Bash** through [`@anthropic-ai/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime) (SRT).
- **Credential masking**: `.env*` files and known credential paths are hidden or value-masked inside the sandbox.
- **`auto` mode**: a small local classifier approves routine workspace actions so you see fewer prompts.

> Status: `0.1.0`, pre-release. See [Security release gate](#security-release-gate) before you rely on it.

## Quick start

Requirements: Node.js `>=23.6.0`, Pi `>=0.84.2`, macOS or Linux. On Linux, also install `bubblewrap`, `socat`, and `ripgrep`:

```bash
# Debian/Ubuntu
sudo apt install bubblewrap socat ripgrep
# Fedora
sudo dnf install bubblewrap socat ripgrep
```

Install the extension. Pin a reviewed commit or tag; this is a security tool, so do not track a moving branch:

```bash
pi install git:github.com/DxTa/pi-sentinel@<commit-or-tag>
```

Start Pi and check that the sandbox works:

```text
/sandbox-status
```

Open the settings panel to see the active mode and where it comes from:

```text
/sentinel
```

That is all you need. The bundled defaults are usable as they are; read [What the defaults do](#what-the-defaults-do) once so you know what is and is not isolated.

### Pick a mode

| Mode | What it does | Good for |
| --- | --- | --- |
| `manual` | Prompts for every gated request. | Reviewing unfamiliar repositories; maximum control. |
| `auto` (default) | A local classifier approves eligible workspace reads, writes, edits, and already-sandboxed Bash. Anything it is unsure about, plus external paths, `.env*`, and network, still prompts. | Daily work with fewer prompts. |
| `yolo` | Approves everything except a short list of [hard rules](#yolo-mode-hard-rules) (system paths, `rm`, `ssh`, `git push`, cluster changes). | Throwaway environments only. |

Change it in `/sentinel` (choose whether it saves to this session, this project, or globally), in config, or per process:

```bash
PI_SENTINEL_MODE=manual pi
```

The first time `auto` mode starts, it downloads the classifier (about 130 MB) from Hugging Face and verifies its SHA-256 hashes. Until the model is ready, or if the download fails, requests prompt as in `manual` mode. Set `"mode": "manual"` if you do not want the download.

### Common config changes

Put overrides in `~/.pi/agent/permissions.json` (all projects) or `<project>/.pi/permissions.json` (one project). Your file only needs the keys you change. Add the schema line for editor completion:

```json
{
  "$schema": "https://raw.githubusercontent.com/DxTa/pi-sentinel/main/schemas/permissions.schema.json",
  "mode": "auto",
  "network": {
    "allowedDomains": ["github.com", "*.npmjs.org", "pypi.org"]
  },
  "permission": {
    "bash": {
      "npm test": "allow",
      "npm run *": "allow",
      "git log *": "allow"
    }
  }
}
```

Run all Bash inside the sandbox, with no network, and fail closed when SRT is unavailable:

```json
{
  "sandbox": {
    "bypassCommands": [],
    "defaultProfile": "offline-dev"
  }
}
```

Keep more prompts in `yolo` or `auto` for commands you care about:

```json
{
  "yoloAskBashPatterns": ["git commit *", "terraform *"]
}
```

## What the defaults do

Read this before trusting the extension:

- **Approved Bash runs on the host, not in the sandbox.** The bundled `sandbox.bypassCommands` is `["*"]`. Exceptions: commands that touch credentials, dotenv files, or Docker are routed through SRT anyway. Set `bypassCommands: []` (see above) to sandbox everything.
- **Bash prompts by default**, except `git status` and `git diff`.
- **Workspace file tools are auto-approved.** `read`, `write`, `edit`, `grep`, `find`, and `ls` inside the workspace run without a prompt after canonical path and symlink checks, in every mode. External paths and symlink escapes prompt. `.env*` writes and edits stay protected.
- **Unknown network domains prompt.** Detection is static: dynamic or obfuscated destinations may be missed. Host-bypassed commands have normal host network access once approved.
- **The sandbox profile is `online-dev`** (network allowed through the domain gate). SRT-wrapped commands can reach local Unix sockets, including Docker, SSH agent, and databases. Docker socket access is host-admin equivalent; set `allowDocker: false` in your sandbox profile when you do not need it.
- **Credentials are masked, not hidden from approved programs.** Sandboxed Bash can read workspace `.env*` and known credential paths read-only. Dotenv values are masked in output; other credential output is replaced with `****`. These files stay write-protected; a protected write target you approve is writable for that one command only.
- **`git push` asks every time**, in every mode, unless an explicit `deny` rule blocks it. The approval is never remembered.
- **`sudo` always prompts** in `manual` and `auto`.
- **Clipboard images**: Pi's own `pi-clipboard-<UUID>.<ext>` temp files can be read without a prompt.

## Commands

| Command | Purpose |
| --- | --- |
| `/sentinel [show\|path\|reset\|help]` | Show or change mode and settings; reset config. |
| `/domain-gate` | Review network-domain policy and approvals. |
| `/sandbox-status` | Check SRT and its host dependencies. |
| `/sandbox-grant path <path> [--ro\|--rw] [--ttl <duration>]` | Grant temporary or persistent filesystem access. |
| `/sandbox-grant network --domain <domain> [--ttl <duration>]` | Grant a sandbox network domain. |
| `/sandbox-revoke <grant-id>` | Revoke a sandbox grant. |

## Reference

### How it works

```text
tool call -> workspace file check, permission rules, path / network gates
          -> auto-mode classifier (eligible local reads/lists/writes/edits and sandboxed Bash)
          -> SRT wrapper or approved host bypass
          -> run, prompt, or deny
```

Deterministic gates always run first. The classifier can only turn a prompt into an allow for eligible requests; it never overrides a deny.

SRT is the only sandbox backend. SRT-wrapped commands can read the repository and working directory, configured binds, standard runtime/system paths, temporary directories, selected home paths such as `~/.config`, `~/.gitconfig`, and `~/.gitignore`, and the pi-sentinel/SRT package roots. The repository and configured writable binds are writable. Known credential paths are masked by patterns, not by complete secret detection; project scripts and tests remain visible inside the repository.

### Commands inside loops and wrappers

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

### `yolo` mode: hard rules

`yolo` lets requests run without a prompt, including external directories, network `ask` verdicts, and writes outside the workspace, except these hard rules:

- **Denied, no prompt:** `write`, `edit`, and readable Bash commands that write to a forbidden path: `/etc`, `/System`, `/Library`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, `/private/etc`, `/var` (except `/var/folders` and `/var/tmp`), `~/.ssh`, `~/.aws`, and `~/.gnupg`. Symlinks into these paths count, including `link/../etc`. Bash writes are redirects (`>`, `>>`, `&>`) and the verbs `cp`, `mv`, `ln`, `install`, `rm`, `touch`, `mkdir`, `tee`, `truncate`, `chmod`, `chown`, `dd of=`, `sed -i`, `curl -o`, and `wget -O`. Reads are never denied.
- **Prompt:** `rm`, `ssh`, `git push`, and kubectl commands that change a cluster (`apply`, `create`, `delete`, `edit`, `patch`, `replace`, `set`, `scale`, `rollout` except `status`/`history`, `drain`, `cordon`, `uncordon`, `taint`, `label`, `annotate`, `autoscale`, `run`, `expose`, `cp`). Matching uses the executable name and subcommand, so `/bin/rm`, `git -C repo push`, and `kubectl -n prod delete` count while `git log --grep push` does not. Add your own with `yoloAskBashPatterns`.
- **Still protected:** explicit `deny` rules in your config, explicit denied network domains, and `.env*` protection. SRT sandbox grant prompts are unchanged.

Limits:

- The forbidden-path check is best effort. It reads only commands the parser can read, so `eval`, interpreter code (`python -c`), and writer commands not in the list (`tar -C`, `unzip -d`, `git clone <dir>`) pass. The SRT sandbox stays on and is the backstop.
- A `cd` inside a subshell is tracked as if it carried over, so a later relative write in the same command can be denied by mistake.
- `kubectl exec` is not treated as a write.

`manual` and `auto` are unchanged, including forced prompts for external writes.

### `auto` mode classifier

pi-sentinel starts or reuses one shared, detached Node worker. It runs the Apache-2.0 Lion Warden classifier, pinned to revision `77888f617584758f904faefd6f38d4cf926f6d5d`. The model and tokenizer are not bundled; first startup downloads about 130 MB into `~/.pi/agent/runtime/pi-sentinel/auto-mode/models`, verifies SHA-256 hashes, and resumes interrupted downloads. The worker fails closed: unavailable or invalid model assets mean permission requests prompt. No Python is required.

What the classifier sees: path/tool metadata for reads and listings, up to 800 characters of write/edit content, or a redacted Bash command. Read output is not sent, so prompt injection inside a file cannot be detected before reading. Sensitive paths, external targets, network operations, unsandboxed Bash, and model failures prompt. Fixed thresholds are authoritative; 5% of would-allow decisions prompt anyway for audit (20% for allows learned from history).

Override the model directory or Unix socket when needed:

```sh
export PI_SENTINEL_AUTO_MODEL_DIR=/path/to/models
export PI_SENTINEL_AUTO_SOCKET=/path/to/auto-mode.sock
```

Each evaluation writes a calibration record to `~/.pi/agent/logs/auto-mode-calibration.jsonl`. Records contain a hash of classifier input, not raw request text. The owner-only file is mode `0600`, rotates at 50 MB, and retains one `.1` file. One worker can serve multiple Pi sessions.

#### Learning from your answers

`auto` stores one row per evaluation in `~/.pi/agent/extensions/pi-sentinel/decision-store/decisions.db` (mode `0600`): head scores, tool, operation, a coarse pattern key, and a hashed workspace. It stores no prompt or command text. Past answers can turn a model prompt into an allow, or force a prompt:

- **Only your dialog answers are labels.** Failures, timeouts, dismissed dialogs, and auto-approvals write no label. Denials stored within 1 second by earlier versions are ignored.
- **The latest explicit decision for a key in a workspace wins.** A denial prompts until a later approval clears it. Denials in at least two other workspaces also prompt.
- **History may resolve only `threat_benign_low_confidence`.** It never overrides injection, threat, tool-action, sensitive-source, or external-sink findings, or a hard rule. The benign score must be at least 0.5.
- **Project allow:** decayed approvals (14-day half-life) of at least 2.5 over at least 2 days, within 30 days. **Global allow:** the same, across at least 3 workspaces with no denying workspace.
- **Audit approvals add no evidence.** Audit denials count as denials. Telemetry records `fusionVersion`, approval weights, days, and denial counts so any rule can be replayed offline.

Run `node scripts/calibration-report.mjs [calibration.jsonl] [review.jsonl]` to join human approval/denial labels by `evaluationId` and print precision/recall by gate and threshold. It includes the rotated calibration file when present; automatic model approvals are not treated as human labels.

Run `node scripts/calibration-report.mjs [calibration.jsonl] [review.jsonl]` to join human approval/denial labels by `evaluationId` and print precision/recall by gate and threshold. It includes the rotated calibration file when present; automatic model approvals are not treated as human labels.

### Configuration precedence

Bundled defaults live in [`config.json`](config.json); the full schema is [`schemas/permissions.schema.json`](schemas/permissions.schema.json). Lowest to highest:

1. bundled defaults;
2. global `~/.pi/agent/permissions.json`;
3. trusted project `<project>/.pi/permissions.json`;
4. per-agent configuration (agent frontmatter);
5. security profile overlay.

Runtime settings (mode, logs, network, sandbox) merge from layers 1–3. Permission rules also merge from agent frontmatter and the active security-profile overlay; those layers do not override runtime settings.

`PI_SENTINEL_MODE` overrides the mode for that process only. It does not change config files. Invalid values are ignored and reported as config issues. Child processes inherit it unless their environment removes it.

In `/sentinel`, every row shows its effective value and the scope it comes from, for example `manual (from project, overrides global: auto)` or `on (default)`. **Save mode to** picks where the next mode change is stored:

- `session`: in memory until the session ends. Overrides `PI_SENTINEL_MODE` and file config.
- `project`: `<project>/.pi/permissions.json`. A committed file changes the mode for everyone who uses the repository.
- `global` (default): `~/.pi/agent/permissions.json`. A project mode still overrides it.

Choosing `project` or `global` replaces an active session mode. The header shows the mode chain on one line (session, `PI_SENTINEL_MODE`, project, legacy project files, global, legacy global, default) with `▶` on the layer in effect. Logs and sandbox settings always write to the global file; when a project file overrides one of them, its row says so and saving warns that the project value still applies.

### Logs

`permissionReviewLog` (default `true`) writes JSONL under `~/.pi/agent/extensions/pi-sentinel/logs/`. Records may include commands, paths, prompt messages, targets, and bounded tool-input previews. `debugLog` (opt-in) records mode, tool/gate metadata, prompt timing and outcome, and `auto_mode.evaluation` phase/latency/provenance metadata, using lengths and hashes instead of prompt bodies. Neither stream is meant to store write content, model payloads, or secret values, but they are not guaranteed to be fully redacted or rotated. Treat both as sensitive, and disable them when not needed.

### Threat model

**Protects:** user files, configured credential-path masks, command authorization, network egress, sandbox boundaries, and accidental destructive actions.

**Untrusted inputs:** model output, tool arguments, MCP and skill requests, project files, shell commands and output, and classifier worker responses.

**Enforcement boundary:** deterministic gates run before execution and before `auto`. SRT denies configured credential-path patterns for wrapped commands. Workspace-local `.env*` files (except `.env.example`) and recognized home credential/config files can be consumed by sandboxed Bash through per-path read-only SRT grants. Matching bundled dotenv denies are bypassed only for those canonical targets; explicit `ask`/`deny` rules and unrelated restrictions remain enforced. Dotenv output masks comments and literal values of at least six characters; generic credential output is fully redacted. Transformed or encoded values may evade dotenv value matching, and an authorized consumer can still transmit or transform a secret subject to the sandbox network policy. Unsandboxed and bypassed Bash cannot use these automatic grants. A bypass is not a sandbox.

**Worker trust:** the configured worker and model cache are trusted components. The socket uses owner-only filesystem permissions, but the protocol does not authenticate the peer or prove response honesty.

**Out of scope:** a compromised host, Pi runtime, dependency, SRT, Docker daemon, or external service; actions you explicitly approve outside SRT; and data exfiltration through an allowed host command or network destination. This extension is not a privilege boundary against a host administrator.

See [`SECURITY.md`](SECURITY.md) for the full policy and how to report a vulnerability.

### Platform support

- macOS and Linux: supported. Linux needs `bwrap`, `socat`, and `rg`.
- Windows: SRT is unavailable. Set `sandbox.bypassCommands: []` so Bash fails closed instead of running unsandboxed.

### Service API

Other Pi extensions can query the process-local permission service:

```typescript
import { getPermissionsService } from "@dxta/pi-sentinel";

const service = getPermissionsService();
const result = service?.checkPermission("bash", "git status");
```

Call `getPermissionsService()` per use so `/reload` and extension load order do not leave a stale reference.

### Security release gate

This repository carries a historical hardening patch for `@anthropic-ai/sandbox-runtime@0.0.59` under [`patches/`](patches/). The current 0.0.75 dependency is pinned for macOS profile compaction; macOS npm installs with lifecycle scripts enabled run `bin/patch-sandbox-runtime.mjs` to split oversized SBPL filter sets into bounded rules and spill oversized profile text to private files while retaining every filter. This does not establish equivalence with the historical hardening patch. Do not publish or tag a security release until that equivalence is verified or the install process applies the historical hardening explicitly.

## Development

```bash
git clone https://github.com/DxTa/pi-sentinel.git
cd pi-sentinel
npm ci
npm run check   # TypeScript
npm test        # Vitest
```

Point Pi at your checkout while developing:

```bash
pi install ./path/to/pi-sentinel
```

Tests live beside the code under `src/`. SRT smoke tests need `bwrap` and `socat` on Linux. Design decisions are recorded in [`docs/journal/decisions/`](docs/journal/decisions/).

## License

MIT. Original upstream attribution (`@gotgenes/pi-permission-system`) is retained in [`LICENSE`](LICENSE). Classifier weights are Apache-2.0.
