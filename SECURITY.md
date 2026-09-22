# Security policy

## Threat model

**Trusted components:** the approving user; global configuration; reviewed project policy; Pi; pi-sentinel and its dependencies; the host account and OS; SRT for commands promised to be wrapped; and the configured Patronus worker and model cache.

**Untrusted inputs:** model-generated tool calls, repository contents, paths and symlinks, MCP and skill responses, command output, network data, and worker responses. Project `.pi/permissions.json` and agent frontmatter are security policy, not ordinary repository data; review them before trusting the repository.

**In scope:** fail-open permission, path, network, sandbox, credential, or destructive-action checks; precedence errors; path traversal or symlink escape; secret or audit-log disclosure; unexpected host bypass; SRT escape; `yolo-auto` authorization outside eligible workspace-local reads/lists or the bounded secret-read route; clipboard provenance or temp-root escape; L3 authorization; worker socket impersonation or protocol confusion; and cache tampering that changes authorization.

**Out of scope:** host administrator or kernel compromise; compromise of the current user account, Pi runtime, explicitly trusted dependency, SRT runtime, Docker daemon, or configured worker; consequences of commands explicitly approved to run on the host; unreviewed project policy; intentionally approved Docker or local Unix-service access; and availability-only failures such as model download or resource exhaustion.

**Residual limits:** classifier decisions use request metadata, not file contents. Secret-scanner approval never disables result redaction. Pattern-based masking cannot identify every secret. Static network preflight may miss dynamic destinations. Clipboard trust covers only tracked interactive direct reads; it does not make temp roots generally visible or authorize Bash. Approved host commands have normal host capabilities; Docker and powerful Unix sockets can be equivalent to host access.

## Report vulnerability

Do not open a public issue for an exploitable vulnerability.

Email the maintainer through the contact listed on the GitHub repository, or use GitHub private vulnerability reporting when enabled. Include:

- affected commit or tag
- host OS and Node.js version
- reproduction steps or proof of concept
- impact and any suggested mitigation

Do not include credentials, tokens, private paths, or customer data in reports.

## Scope

Permission decisions, network domain gating, sandbox isolation, credential filtering, masked paths, grants, audit logging, and model-backed approval are security-sensitive. Reports involving fail-open behavior receive priority.

On macOS and Linux, SRT-wrapped commands can reach local Unix sockets by default. This can expose Docker, SSH agents, databases, and other local services. Docker access remains separately gated by normal command permission, but approving a command does not make local Unix services safe to expose.

Supported security fixes are released from reviewed Git tags. Verify checksums or commit signatures when your deployment process supports them.
