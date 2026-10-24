# Changelog

All notable changes are documented here (Keep a Changelog style).

## [Unreleased]

### Changed
- Product renamed to **Daemonica** in all identifiers, paths and packages (SPEC v1.3).
- Dark theme is the default; new app icon; navigation and header use icons; planned modules are listed as "soon".

### Added
- M1.0 foundation (standard library only): versioned RPC protocol, privileged helper with
  `SO_PEERCRED`-checked Unix sockets and typed operation allowlist, Annex-A policy table,
  hash-chained audit log, Plan→Apply→Confirm framework with rollback journal, TLS 1.3 config,
  accept-time network allowlist, security middleware (CSP, CSRF, RFC 9457), rate limiting,
  bootstrap tokens, `daemonica-admin` (bootstrap, status, allowlist-reset, audit-verify),
  hardened systemd units, `.deb` build script, placeholder UI shell.
