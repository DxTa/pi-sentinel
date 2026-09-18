# Security policy

## Report vulnerability

Do not open a public issue for an exploitable vulnerability.

Email the maintainer through the contact listed on the GitHub repository, or use GitHub private vulnerability reporting when enabled. Include:

- affected commit or tag
- host OS and Node.js version
- reproduction steps or proof of concept
- impact and any suggested mitigation

Do not include credentials, tokens, private paths, or customer data in reports.

## Scope

Permission decisions, network domain gating, sandbox isolation, credential filtering, masked paths, grants, and audit logging are security-sensitive. Reports involving fail-open behavior receive priority.

On macOS and Linux, pi-sentinel enables unrestricted Unix-socket access inside sandboxed commands by default. This is intentionally broader than path-scoped socket access: sandboxed code can reach Docker, SSH agents, databases, and other local Unix services. Docker access remains separately gated by the normal command permission check, but approval of a non-Docker command does not make local Unix services safe to expose.

Supported security fixes are released from reviewed Git tags. Verify checksums or commit signatures when your deployment process supports them.
