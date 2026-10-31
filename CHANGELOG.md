# Changelog

## 0.1.0 — unreleased

Standalone Git distribution prepared for `DxTa/pi-sentinel`.

- Renamed the `yolo-auto` mode to `auto`, with no compatibility alias: set `"mode": "auto"`. Environment variables are `PI_SENTINEL_AUTO_MODEL_DIR` and `PI_SENTINEL_AUTO_SOCKET`; the model cache is `runtime/pi-sentinel/auto-mode/models`; calibration logs are `auto-mode-calibration.jsonl`; debug events use the `auto_mode.` prefix.
- `/sentinel` shows each row's effective value and source scope (`manual (project)`, `on (default)`, `off (project, overrides global)`), with a compact one-line mode chain instead of the paged chain.
- Removed the "Mode saves to" row: a mode change saves to the scope that currently sets the mode (session above `PI_SENTINEL_MODE`; global for bundled defaults). Added `/sentinel mode <manual|yolo|auto> [session|project|global]` to store the mode in a specific scope.
- Fixed `/sentinel` writing effective values to the global file: toggling a log setting copied the effective mode and merged `yoloAskBashPatterns` (including project values) into `~/.pi/agent/permissions.json`. Only the changed key is written now.
- Fixed the `/sentinel` sandbox row ignoring a project `sandbox.enabled`, and log toggles applying in-session despite a project override.
- Rewrote the README around a quick start, mode comparison, and the security-relevant defaults.

- Preserved permission, network, sandbox, masked-path, grant, service, and backend behavior.
- Removed content-based credential scanning and approval; configured SRT masks and permission/path rules remain.
- Resolved bundled bubblewrap runner relative to installed package root.
- Removed environment-specific semantic-search trust behavior.
- Excluded private grants, logs, generated state, and parent-repository tests.
- Retained upstream `@gotgenes/pi-permission-system` attribution and MIT license.

Release remains gated on replacing the local sandbox-runtime hardening patch with an equivalent released dependency. SRT 0.0.75 was reviewed: it improves related macOS rule ordering and filtering, but still emits `file-write-create` move blocks for denied roots and ancestors, so it is not treated as equivalent.
