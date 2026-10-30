# Changelog

All notable changes are documented here (Keep a Changelog style).

## [Unreleased]

## [0.1.0~rc2] — 2026-10-30 — Phase 1 release candidate

Release candidate for the Phase 1 acceptance (SPEC §6.6). Unsigned test build
(`-UNSIGNED-TESTONLY`). Acceptance checklist: `docs/acceptance/ACCEPTANCE-PHASE-1.md`;
test report: `docs/acceptance/TEST-REPORT-PHASE-1.md`; security audit:
`docs/security/AUDIT-PHASE-1.md`.

### Added
- **Foundation (M1.0):** privileged helper on `SO_PEERCRED`-checked Unix sockets with a typed
  operation allowlist and deny-by-default policy (Annex A); unprivileged web process; TLS 1.3;
  network allowlist enforced before the TLS handshake; CSP with Trusted Types, CSRF, security
  headers; rate limits with backoff; passkey-only login (WebAuthn with user verification) verified
  in the helper; step-up (5 min); bootstrap, invitation and recovery tokens; setup wizard (token,
  domain, allowlist, certificate, first passkey); accounts, roles, passkeys and sessions; settings;
  hash-chained audit log with viewer and verification; Plan → Apply → Confirm with automatic
  rollback; `daemonica-admin` (bootstrap, status, recover, list-accounts, allowlist-reset,
  audit-verify, tls-status, tls-issue, tls-install); German and English UI, dark and light theme.
- **Overview, services, logs, processes (M1.1):** system overview with last logins; systemd
  services with actions and unit journal; journald viewer with live follow, filters, export,
  allowlisted log files under `/var/log` and a hint for messages lost to journald rate limiting;
  process list with signals (operators: own processes).
- **Users and SSH keys (M1.2):** Linux users and groups with last login; `authorized_keys`
  management with validation and read-only `sshd` view.
- **Files (M1.3):** file manager with editor (CodeMirror), upload/download, validators and
  pre-versions for `/etc`, symlink-safe operations in a per-user worker.
- **Web terminal (M1.4):** xterm.js terminals as transient systemd units, elevated mode for admins.
- **Network and firewall (M1.5):** network configuration (netplan, ifupdown) with
  Plan → Apply → Confirm; ufw status, rule editor with plain-language explanations and
  reachability check; firewall logs with statistics and export; packet capture with a guided
  filter, live view and download.
- **Tasks and jobs (M1.6):** systemd timers and cron with a schedule builder, script library with
  local scripts and GitHub collections pinned to a commit.
- **Updates, disks, time and host (M1.7):** apt updates and packages as background jobs,
  unattended-upgrades, package sources, needrestart; disks, mounts and fstab with verification;
  time zone, NTP, host name, reboot and power-off.
- **Certificates (M1.8, DEC-034):** Let's Encrypt over HTTP-01, TLS-ALPN-01 or guided DNS-01, or
  an own certificate, in the wizard and in the settings; temporary firewall window for the ACME
  check; automatic renewal for HTTP-01/TLS-ALPN-01; hot reload without logging users out.
- **Quality (M1.8):** end-to-end test with Chromium's virtual WebAuthn authenticator over setup,
  all modules, step-up, invitations, all three roles, logout/login and anonymous access, plus a
  base load of 50 sessions and the idle memory check (`make test-e2e`); CycloneDX SBOM
  (`make sbom`); `make sec` with govulncheck, osv-scanner, gosec, gitleaks and npm audit.

### Changed
- Product named **Daemonica** in all identifiers, paths and packages (SPEC v1.3).
- Hardening (M1.8): `NoNewPrivileges`, `RestrictNamespaces`, a system call filter and a reduced
  capability set for the helper (exposure 7.0 → 5.1; web 1.1).
- Rate limits count IPv6 clients per /64 (audit F-01).
- Audit log is append-only (`chattr +a`) and rotates at 32 MiB with the hash chain continued
  across files (DEC-035, audit F-02).
- `golang.org/x/net` 0.62.0, `go-jose/v4` 4.1.6 (audit F-14).

### Fixed
- Automatic certificate renewal stays on after upgrading an installation from before M1.8 (audit F-16).
- Last logins on hosts without wtmpdb/lastlog2 (Ubuntu 26.04 without `pam_wtmpdb`) come from sshd's journal lines.
- Firewall log view shows entries suppressed by kernel rate limiting (audit F-13).
- An expired or untrusted dashboard certificate can be replaced from the console (audit F-12).
- Purge removes job units, the ACME window and the append-only flag; a newer database schema is
  refused instead of being opened by an older version.
