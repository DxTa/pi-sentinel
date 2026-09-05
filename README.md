# pi-sentinel

Pi extension for permission enforcement, network domain gating, sandboxed Bash, and credential protection.

Derived from [`@gotgenes/pi-permission-system`](https://github.com/gotgenes/pi-packages/tree/main/packages/pi-permission-system), with domain gating, SRT/bubblewrap/Gondolin sandbox integration, masked-file handling, and credential protection added by DxTa.

## Install

First release is Git-only. Install a reviewed tag or commit:

```bash
pi install git:github.com/DxTa/pi-sentinel@v0.1.0
```

Pi clones the package and runs `npm install`. The package exposes `./src/index.ts` through its `pi.extensions` manifest; no build step is required.

The future npm name is `@dxta/pi-sentinel`. npm publication is not part of the first release.

## Security model

- **Permission policy:** `allow`, `deny`, or `ask` for tools, paths, Bash commands, MCP, skills, and external directories.
- **Network gate:** extracts domains from Bash and applies allow/deny/ask rules.
- **Sandbox:** SRT is the default backend; bubblewrap is the legacy Linux backend; Gondolin is available for its configured profile/runtime path.
- **Credential protection:** blocks or redacts secret environment variables and sensitive file reads through `sentinelCreds`.
- **Masked paths:** `.env`, keys, certificates, SSH credentials, cloud credentials, and Pi credentials are masked. `ls`/`find` may show names; content is replaced or denied.
- **Audit logs:** permission decisions and optional debug diagnostics are written as JSONL.

Sandbox failures block execution. This extension does not make an unsupported host safe by falling back to unsandboxed execution.

## Configuration

Bundled defaults live in `config.json`.

Precedence, lowest to highest:

1. Bundled defaults
2. Global `~/.pi/agent/permissions.json`
3. Trusted project `<project>/.pi/permissions.json`
4. Per-agent frontmatter
5. Security profile overlay

Legacy project/global paths remain supported for compatibility. Use project overrides only in trusted repositories. Last matching wildcard rule wins; `permission.path` is a cross-cutting gate.

Minimal configuration:

```json
{
  "permission": {
    "*": "ask",
    "read": "allow",
    "write": "deny",
    "path": { "*": "allow", "*.env": "deny" }
  },
  "network": {
    "enabled": true,
    "unknownDomains": "ask",
    "allowedDomains": ["registry.npmjs.org"],
    "deniedDomains": []
  },
  "sandbox": {
    "enabled": true,
    "backend": "srt",
    "defaultProfile": "online-dev"
  }
}
```

See [`schemas/permissions.schema.json`](schemas/permissions.schema.json) for all options.

## Commands

```text
/sentinel [show|path|reset|help]
/domain-gate
/sandbox-status
/sandbox-grant path <path> [--ro|--rw] [--ttl 30m]
/sandbox-grant network --domain example.com [--ttl 30m]
/sandbox-revoke <grant-id>
```

`yoloMode` auto-approves `ask` checks. Keep it disabled unless unattended execution is intentional.

## Host requirements

- Node.js `>=23.6.0` for the bundled Gondolin dependency.
- Linux: SRT requires `rg`, `bwrap`, and `socat`; bubblewrap also requires a working `bwrap` installation.
- macOS: SRT requires its native/runtime support and Command Line Tools for the Git execution shim when applicable.
- Windows: permission and network checks work, but SRT and bubblewrap backends are unavailable.

Set `PI_BWRAP_RUNNER` or configure `sandbox.runnerPath` only when using an explicitly reviewed runner. The default runner is resolved relative to this installed package.

## SRT release gate

This repository currently carries a historical patch for `@anthropic-ai/sandbox-runtime@0.0.59` under `patches/`. Pi Git installs use npm and do not apply pnpm patches. Do not publish or tag a security release until an upstream/fixed released dependency replaces that patch; never silently drop the hardening.

## Development

```bash
npm install
npm test
npm run check
npm run check:shell
```

Tests live beside implementation under `src/` and in `tests/`. Package-local tests must not require this repository or any parent checkout.

## Service API

Other extensions can query the published service through the future npm identity:

```typescript
import { getPermissionsService } from "@dxta/pi-sentinel";

const service = getPermissionsService();
const result = service?.checkPermission("bash", "git status");
```

## Attribution and license

MIT-licensed derivative. Original upstream copyright and attribution are retained in [`LICENSE`](LICENSE). New DxTa changes are identified in repository history and release notes.
