# Security policy

Daemonica is pre-release software. Please do not deploy it on production systems yet.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the project owner (tnebert@gmail.com),
not via public issues. Include affected version, reproduction steps and impact.

## Design principles

- Passkey-only authentication (WebAuthn, user verification required); no passwords, no fallback.
- Privilege separation: unprivileged web process, small root helper with a typed operation allowlist.
- Network allowlist enforced before the TLS handshake; loopback-only by default.
- Tamper-evident audit log (SHA-256 hash chain), verifiable with `daemonica-admin audit-verify`.

Per-phase security audit reports are stored in `docs/security/`.
