# pi-sentinel

Security extension for the [Pi coding agent](https://github.com/earendil-works/pi). For every tool call it decides: allow, prompt you, or block.

- Permission rules for `read`, `write`, `edit`, `bash`, MCP tools, and skills.
- Network domain gate: prompts before Bash reaches a domain you have not allowed.
- Sandboxed Bash via [`@anthropic-ai/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime) (SRT).
- Credential masking for `.env*` and known credential paths.
- `auto` mode: a local classifier approves routine workspace actions, so you see fewer prompts.

> Status: `0.1.0`, pre-release. Read [What the defaults do](#what-the-defaults-do) before you rely on it.

## Getting started

1. Install Node.js `>=23.6.0` and [Pi](https://github.com/earendil-works/pi):

   ```bash
   brew install node        # macOS. On Ubuntu/Debian apt's Node.js is too old: use nvm or NodeSource
   npm install -g @earendil-works/pi-coding-agent
   ```

2. Linux only, for the Bash sandbox (macOS has one built in):

   ```bash
   sudo apt install bubblewrap socat     # Fedora: sudo dnf install bubblewrap socat
   ```

3. Install pi-sentinel. Pin a reviewed commit or tag, not a branch:

   ```bash
   pi install git:github.com/DxTa/pi-sentinel@<commit-or-tag>
   ```

4. Start `pi` and run `/sandbox-status`. If something is still missing, it prints the command that fixes it, such as the AppArmor rule Ubuntu 24.04+ needs for bubblewrap ([why](docs/reference.md#linux-sandbox-setup)).

That's it: the defaults work as they are. `auto` mode needs Apple silicon on macOS; on Intel Macs use `manual` or `yolo`.

## Modes

| Mode | Behavior | Use for |
| --- | --- | --- |
| `manual` | Prompts for every gated request. | Unfamiliar repositories. |
| `auto` (default) | Local classifier approves eligible workspace reads, writes, edits, and sandboxed Bash. Uncertain, external, `.env*`, and network requests still prompt. | Daily work. |
| `yolo` | Approves everything except [hard rules](docs/reference.md#yolo-mode-hard-rules) (system paths, `rm`, `ssh`, `git push`, cluster changes). | Throwaway environments only. |

```text
/sentinel mode manual           # save where the mode is currently set
/sentinel mode auto project     # or: session | project | global
```

```bash
PI_SENTINEL_MODE=manual pi      # this process only
```

On first start, `auto` downloads a ~320 MB model from Hugging Face (CPU only, hash-verified). Until it is ready, or if it fails, requests prompt as in `manual`. Set `"mode": "manual"` to skip the download.

## Configuration

Global: `~/.pi/agent/permissions.json`. Per project: `<project>/.pi/permissions.json`. Include only the keys you change:

```json
{
  "$schema": "https://raw.githubusercontent.com/DxTa/pi-sentinel/main/schemas/permissions.schema.json",
  "mode": "auto",
  "network": { "allowedDomains": ["github.com", "*.npmjs.org", "pypi.org"] },
  "permission": {
    "bash": { "npm test": "allow", "npm run *": "allow", "git log *": "allow" }
  },
  "yoloAskBashPatterns": ["git commit *", "terraform *"]
}
```

Sandbox all Bash with no network, and fail closed when SRT is unavailable:

```json
{ "sandbox": { "bypassCommands": [], "defaultProfile": "offline-dev" } }
```

Bundled defaults: [`config.json`](config.json). Precedence and all options: [reference](docs/reference.md#configuration-precedence).

## What the defaults do

- Approved Bash runs on the host, not in the sandbox (`bypassCommands: ["*"]`). Commands touching credentials, dotenv files, or Docker still go through SRT. Use `bypassCommands: []` to sandbox everything.
- Bash prompts, except `git status` and `git diff`. `sudo` always prompts in `manual` and `auto`. `git push` prompts every time in every mode.
- Workspace file tools (`read`, `write`, `edit`, `grep`, `find`, `ls`) run without a prompt after path and symlink checks. External paths prompt; `.env*` stays write-protected.
- Unknown network domains prompt. Detection is static, so obfuscated destinations can be missed.
- Sandbox profile `online-dev` allows local Unix sockets, including Docker (host-admin equivalent). Set `allowDocker: false` in your profile if you do not need it.
- Credentials are masked in output, not hidden from approved programs.

## Commands

| Command | Purpose |
| --- | --- |
| `/sentinel [show\|mode\|path\|reset\|help]` | Show or change mode and settings. |
| `/domain-gate` | Review network-domain policy and approvals. |
| `/sandbox-status` | Check SRT and its host dependencies. |
| `/sandbox-grant path <path> [--ro\|--rw] [--ttl <duration>]` | Grant filesystem access. |
| `/sandbox-grant network --domain <domain> [--ttl <duration>]` | Grant a network domain. |
| `/sandbox-revoke <grant-id>` | Revoke a grant. |

## More

- [Reference](docs/reference.md): how it works, `yolo` hard rules, `auto` classifier, logs, threat model, service API, security release gate.
- [SECURITY.md](SECURITY.md): security policy and vulnerability reporting.

## Development

```bash
git clone https://github.com/DxTa/pi-sentinel.git && cd pi-sentinel
npm ci
npm run check && npm test
pi install ./                   # use your checkout in Pi
```

## License

MIT. Upstream attribution (`@gotgenes/pi-permission-system`) is in [`LICENSE`](LICENSE). Classifier weights are Apache-2.0.
