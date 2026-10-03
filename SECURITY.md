# Security policy

## Threat model

**Trusted components:** the approving user; global configuration; reviewed project policy; Pi; pi-sentinel and its dependencies; the host account and OS; SRT for commands promised to be wrapped; and the configured Patronus worker and model cache.

**Untrusted inputs:** model-generated tool calls, repository contents, paths and symlinks, MCP and skill responses, command output, network data, and worker responses. Project `.pi/permissions.json` and agent frontmatter are security policy, not ordinary repository data; review them before trusting the repository.

**In scope:** fail-open permission, path, network, sandbox, masked-path, or destructive-action checks; precedence errors; path traversal or symlink escape; secret or audit-log disclosure; unexpected host bypass; SRT escape; `yolo-auto` authorization outside eligible workspace-local reads/lists and already-sandboxed Bash; clipboard provenance or temp-root escape; L3 authorization; worker socket impersonation or protocol confusion; and cache tampering that changes authorization.

**Out of scope:** host administrator or kernel compromise; compromise of the current user account, Pi runtime, explicitly trusted dependency, SRT runtime, Docker daemon, or configured worker; consequences of commands explicitly approved to run on the host; unreviewed project policy; intentionally approved Docker or local Unix-service access; and availability-only failures such as model download or resource exhaustion.

**Residual limits:** classifier decisions use request metadata, not file contents. Path-pattern masking applies only to configured paths; it does not scan arbitrary file content or tool results. Static network preflight may miss dynamic destinations. Clipboard trust covers only tracked interactive direct reads; it does not make temp roots generally visible or authorize Bash. Approved host commands have normal host capabilities; Docker and powerful Unix sockets can be equivalent to host access.

## Report vulnerability

Do not open a public issue for an exploitable vulnerability.

Email the maintainer through the contact listed on the GitHub repository, or use GitHub private vulnerability reporting when enabled. Include:

- affected commit or tag
- host OS and Node.js version
- reproduction steps or proof of concept
- impact and any suggested mitigation

Do not include credentials, tokens, private paths, or customer data in reports.

## Scope

Permission decisions, network domain gating, sandbox isolation, masked-path enforcement, grants, audit logging, and model-backed approval are security-sensitive. Reports involving fail-open behavior receive priority.

On macOS and Linux, SRT-wrapped commands can reach local Unix sockets by default. This can expose Docker, SSH agents, databases, and other local services. Docker access remains separately gated by normal command permission, but approving a command does not make local Unix services safe to expose.

Supported security fixes are released from reviewed Git tags. Verify checksums or commit signatures when your deployment process supports them.
## Workspace file approval and diagnostics

Normal workspace-local `read`, `write`, `edit`, `grep`, `find`, and `ls` operations may be auto-approved in every permission mode only after canonical containment checks. Existing targets and canonical parents for new writes are checked; symlink targets that leave the session workspace and external paths do not qualify. Bash is not covered by this rule.

Workspace `.env*` reads follow the ordinary permission/path rules; there is no result-scanning exception. `.env*` writes and edits remain on the protected path flow.

The opt-in debug log records bounded permission, prompt, phase, latency, failure, decision, and model-provenance metadata. Prompt bodies, write content, raw model payloads, and secret values must not be added to debug records. Review and debug logs are sensitive local artifacts and require the same filesystem protection as other agent state.
