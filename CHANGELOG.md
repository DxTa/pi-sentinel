# Changelog

## 0.1.0 — unreleased

Standalone Git distribution prepared for `DxTa/pi-sentinel`.

- Renamed the `yolo-auto` mode to `auto`, with no compatibility alias: set `"mode": "auto"`. Environment variables are `PI_SENTINEL_AUTO_MODEL_DIR` and `PI_SENTINEL_AUTO_SOCKET`; the model cache is `runtime/pi-sentinel/auto-mode/models`; calibration logs are `auto-mode-calibration.jsonl`; debug events use the `auto_mode.` prefix.
- `/sentinel` shows each row's effective value and source scope (`manual (project)`, `on (default)`, `off (project, overrides global)`), with a compact one-line mode chain instead of the paged chain.
- Removed the "Mode saves to" row: a mode change saves to the scope that currently sets the mode (session above `PI_SENTINEL_MODE`; global for bundled defaults). Added `/sentinel mode <manual|yolo|auto> [session|project|global]`, with autocomplete for the mode and scope, to store the mode in a specific scope. In the panel, Enter on Mode opens a picker with the current scope plus session and project overrides, limited to scopes where the change takes effect.
- Fixed `/sentinel` writing effective values to the global file: toggling a log setting copied the effective mode and merged `yoloAskBashPatterns` (including project values) into `~/.pi/agent/permissions.json`. Only the changed key is written now.
- Fixed the `/sentinel` sandbox row ignoring a project `sandbox.enabled`, and log toggles applying in-session despite a project override.
- `auto` mode: the worker loads ONNX Runtime before downloading the model, so an unsupported platform or broken install fails immediately instead of after a 130 MB download. Pi warns once when `auto` falls back to prompting, and `/sentinel show` reports `autoModeWorker=stopped` with the log path. A test runs real CPU inference so a broken runtime install fails `npm test`.
- `auto` mode uses the FP16 Lion Warden model by default (~320 MB download, was the ~130 MB int8 build), with JSON tool-call input and per-operation thresholds from `npm run calibrate`. Model settings live in `profiles/models/<id>.json`. MCP tool calls are classified: only calls the model reads as read or list can skip the prompt; destructive-hinted tools and SQL writes always prompt. `rm`, `ssh`, `git push`, package publish and cluster writes now prompt in `auto` even when the model allows. Writes telling an AI agent to drop its rules always prompt. `permission.mcp` patterns apply to `mcp__<server>__<tool>` tools.
- Rewrote the README around a quick start, mode comparison, and the security-relevant defaults. Detailed reference moved to `docs/reference.md`.
- Linux sandbox no longer needs a system `ripgrep`: the binary ships through `@vscode/ripgrep` (npm platform packages, no install-time download) and is passed to SRT as `ripgrep.command`. `rg` on `PATH` remains the fallback. `/sandbox-status` checks the binary SRT will actually use.
- `/sandbox-status` on Linux runs a short bubblewrap test and prints the fix: the install command for missing packages (apt, dnf, pacman, zypper), or a bwrap-only AppArmor profile when Ubuntu 24.04+'s user-namespace restriction blocks it. Commands blocked for missing dependencies point to `/sandbox-status`.

- Preserved permission, network, sandbox, masked-path, grant, service, and backend behavior.
- Removed content-based credential scanning and approval; configured SRT masks and permission/path rules remain.
- Resolved bundled bubblewrap runner relative to installed package root.
- Removed environment-specific semantic-search trust behavior.
- Excluded private grants, logs, generated state, and parent-repository tests.
- Retained upstream `@gotgenes/pi-permission-system` attribution and MIT license.

Release remains gated on replacing the local sandbox-runtime hardening patch with an equivalent released dependency. SRT 0.0.75 was reviewed: it improves related macOS rule ordering and filtering, but still emits `file-write-create` move blocks for denied roots and ancestors, so it is not treated as equivalent.
