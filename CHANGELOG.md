# Changelog

## 0.1.0 — unreleased

Standalone Git distribution prepared for `DxTa/pi-sentinel`.

- Preserved permission, network, sandbox, credential, masking, grant, service, and backend behavior.
- Resolved bundled bubblewrap runner relative to installed package root.
- Removed environment-specific semantic-search trust behavior.
- Excluded private grants, logs, generated state, and parent-repository tests.
- Retained upstream `@gotgenes/pi-permission-system` attribution and MIT license.

Release remains gated on replacing the local sandbox-runtime hardening patch with an equivalent released dependency. SRT 0.0.75 was reviewed: it improves related macOS rule ordering and filtering, but still emits `file-write-create` move blocks for denied roots and ancestors, so it is not treated as equivalent.
