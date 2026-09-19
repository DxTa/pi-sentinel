# pi-sentinel

Pi extension for permission enforcement, network-domain gating, sandboxed Bash, and credential protection.

## Install

Install a reviewed tag or commit:

```bash
pi install git:git@github.com:DxTa/pi-sentinel@<reviewed-tag-or-commit>
```

Git is the supported distribution path. No build step is required. The npm name is reserved but not published.

## Security defaults

- Direct reads are allowed; writes and edits are denied.
- Bash asks by default, except `git status` and `git diff`.
- Recognized literal network destinations not on the allowlist require approval. Domain preflight uses static command extraction; dynamic or obfuscated destinations may not be identified. Host-bypassed commands have normal host network access after Bash approval.
- `yolo-auto` is enabled for eligible workspace-local reads and listings. Deterministic permission, path, credential, network, sandbox, and destructive-action gates still run first.
- SRT is enabled with the network-capable `online-dev` profile.
- **Approved Bash runs on the host by default** because bundled `sandbox.bypassCommands` is `['*']`. Set it to `[]` to require SRT wrapping and fail closed when SRT is unavailable.
- SRT-wrapped commands can reach local Unix sockets by default. This includes Docker, SSH-agent, and database sockets.
- Docker socket access is host-admin equivalent. Treat Docker approval as host access.

## Threat model

**Protects:** user files and credentials, command authorization, network egress, sandbox boundaries, and accidental destructive actions.

**Untrusted inputs:** model output, tool arguments, MCP and skill requests, project files, shell commands and output, and external worker responses.

**Enforcement boundary:** deterministic gates run before execution and before `yolo-auto`. Credential files and secret environment variables are masked or denied. Non-bypassed Bash is wrapped by SRT; bypassed Bash has normal host filesystem and network access after permission and network preflight. A bypass is not a sandbox.

**Model safety:** `yolo-auto` considers only eligible ask-state workspace-local `read`, `find`, `grep`, and `ls` requests. The worker receives bounded metadata, not file contents, prompts, commands, or tool output; it cannot detect prompt injection inside a file before reading it. At maximum level `l1`, an accepted, complete, non-degraded safe L1 result can authorize. Levels `l2` and `l3` require exact accepted L2 results. Missing, stale, malformed, degraded, uncertain, or timed-out results prompt. L3 is advisory only and never authorizes an escalated request.

**Worker trust:** the configured worker and model cache are trusted components. The socket uses owner-only filesystem permissions, but the protocol does not authenticate the peer or prove response honesty.

**Out of scope:** a compromised host, Pi runtime, dependency, SRT, Docker daemon, or external service; actions the user explicitly approves outside SRT; and data exfiltration through an allowed host command or network destination. This extension is not a privilege boundary against a host administrator.

See [`SECURITY.md`](SECURITY.md) for reporting instructions.

## How it works

```text
request -> permission/path/network/credential gates
        -> yolo-auto only for eligible local reads/lists
        -> SRT wrapper or approved host bypass
        -> execute or prompt/deny
```

SRT is the only sandbox backend. SRT-wrapped commands can read the repository and working directory, configured binds, standard runtime/system paths, temporary directories, selected home paths such as `~/.config`, `~/.gitconfig`, and `~/.gitignore`, and the pi-sentinel/SRT package roots. The repository and configured writable binds are writable. Known credential paths are masked by patterns, not by complete secret detection; project scripts and tests remain visible inside the repository.

## `yolo-auto` worker

The external worker provides Patronus native L1, L2, and advisory L3. The MIT package does not include Patronus Ark, model assets, or commercial/GPL assets.

The adapter requests downloads only during startup, checks pinned revision markers and manifest SHA-256 values for the required L2 packages, warms required models, holds a startup lock, and listens on a user-owned Unix socket. It does not independently hash every model/tokenizer artifact or authenticate socket peers. Permission decisions never download assets. A shared active socket can serve multiple Pi sessions; worker failure falls back to prompting.

When `yoloAutoMode` is enabled, pi-sentinel starts the adapter with `python3` unless the configured socket is already active. Override these when needed:

```sh
export PI_SENTINEL_PYTHON=/path/to/python
export PI_SENTINEL_PATRONUS_SITE_PACKAGES=/path/to/patronus/site-packages
export PI_SENTINEL_YOLO_AUTO_SOCKET=/path/to/yolo-auto.sock

python3 bin/patronus-yolo-auto-worker.py \
  --site-packages /path/to/patronus/site-packages \
  --model-dir /path/to/patronus/models
```

Use `--no-download-files` for offline startup. Missing assets then stop the worker instead of falling back to downloads during a permission decision. `/sentinel show` reports worker state and fallback reason.

## Commands

| Command | Purpose |
| --- | --- |
| `/sentinel [show\|path\|reset\|help]` | Inspect or reset pi-sentinel configuration. |
| `/domain-gate` | Review network-domain policy and approvals. |
| `/sandbox-status` | Check SRT and sandbox dependencies. |
| `/sandbox-grant path <path> [--ro\|--rw] [--ttl <duration>]` | Grant temporary or persistent filesystem access. |
| `/sandbox-grant network --domain <domain> [--ttl <duration>]` | Grant a sandbox network domain. |
| `/sandbox-revoke <grant-id>` | Revoke a sandbox grant. |

`yoloMode` is separate from `yoloAutoMode`: it can auto-approve eligible `ask` checks, including some external reads and local writes. It still prompts for protected Bash patterns and first-time external writes. Keep it off unless unattended execution is intentional.

## Logs

`permissionReviewLog` defaults to `true` and writes JSONL under `~/.pi/agent/extensions/pi-sentinel/logs/`. Records may include commands, paths, prompt messages, targets, and bounded tool-input previews. Treat logs as sensitive; they are not guaranteed to be fully redacted or automatically rotated. Disable review logging when it is not required and restrict the agent directory to the owning user.

## Configuration

Bundled defaults live in [`config.json`](config.json). Precedence, lowest to highest:

1. bundled defaults;
2. global `~/.pi/agent/permissions.json`;
3. trusted project `<project>/.pi/permissions.json`;
4. per-agent configuration;
5. security profile overlay.

Use [`schemas/permissions.schema.json`](schemas/permissions.schema.json) for the complete schema. Runtime settings merge from bundled defaults, global `~/.pi/agent/permissions.json`, and trusted project `<project>/.pi/permissions.json`, with project settings highest. Permission rules additionally merge from global/project agent frontmatter and the active security-profile overlay; those layers do not override general runtime settings.

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

This repository carries a historical hardening patch for `@anthropic-ai/sandbox-runtime@0.0.59` under [`patches/`](patches/). Git installs use npm and do not apply pnpm patches automatically. Do not publish or tag a security release until an upstream fixed release replaces the patched dependency or the install process applies the hardening explicitly.

## License

MIT. Original upstream attribution is retained in [`LICENSE`](LICENSE).
