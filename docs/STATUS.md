# Status (progress against SPEC v1.2)

_Last updated: 2026-10-24_

## Current phase: Phase 1 — milestone M1.0 (in progress)

### Blockers (need owner action)

| # | Blocker | SPEC | Needed from owner |
|---|---|---|---|
| B1 | ~~Test VM access~~ — resolved 2026-10-24 (SSH via the owner's computer; connection through the local egress proxy is intermittently unstable). | S2, §6.1 | — |
| B2 | ~~Package registries blocked~~ — worked around: the test VM has full egress, builds run there (DEC-011). Original issue: in the build environment: `proxy.golang.org`, `sum.golang.org`, `registry.npmjs.org`, `gitlab.com`, `go.googlesource.com`. Without them neither WebAuthn/SQLite/PTY/WebSocket libraries nor the React frontend can be built in a verifiable way (DEC-002). | §4.1, §4.4, D-01 | Allow these domains for Claude (claude.ai → Settings → Capabilities, or org admin), **or** build on the test VM once B1 is solved. |
| B3 | **Push to GitHub refused**: the Claude GitHub App has no write access to `PanPakaPancake/daemonica`. Commits exist locally only. | — | Install the Claude GitHub App for the repo or reconnect GitHub in claude.ai settings. |
| B4 | ~~Go toolchain~~ — Go 1.27.3 installed on the VM from go.dev (SHA-256 verified against go.dev's release index); `go.mod` raised to 1.27.3. | §4.1 | — |
| B5 | ~~Branding assets~~ — logo and app icon supplied by the owner (2026-10-24), in `assets/branding/`. | §5.4 | — |
| B6 | Package signing key. | S2, §4.3 | Later (release candidate); until then artifacts are `-UNSIGNED-TESTONLY`. |

### Test VM (first inspection 2026-10-24)

| Item | Finding |
|---|---|
| OS / kernel | Ubuntu 26.04.1 LTS (Resolute Raccoon), Linux 7.0.0-38-generic, x86_64 |
| Resources | 2 vCPU, 7.7 GiB RAM, 96 GB disk (2 % used) |
| Network | eth0 148.230.104.4/24 **and IPv6 2a02:4780:41:d243::1/48** (test_vm.md said "none"); netplan (`50-cloud-init.yaml`) with systemd-networkd |
| Listening | sshd :22 (v4+v6), systemd-resolved, chronyd, `monarx-agent` (Hostinger security agent) on loopback |
| Firewall | ufw installed, **inactive**; nftables empty |
| sshd | PermitRootLogin yes, PasswordAuthentication yes (to be addressed by the Phase-2 checklist; no change now, A-11) |
| Users | no regular users (UID ≥ 1000) — a non-root Linux user is required for the first admin account (SPEC §3.4) |
| Pending updates | 22 |
| Snapshots / console | available (owner) |
| Egress | proxy.golang.org, sum.golang.org, registry.npmjs.org, go.dev, github.com, Let's Encrypt staging: all reachable |
| Build tooling installed | Go 1.27.3 (go.dev, checksum-verified), nodejs 22 / npm 9 / make / shellcheck (Ubuntu archive), govulncheck |

### Test-VM operational notes

- 2026-10-24: `/etc/ssh/sshd_config.d/90-daemonica-dev.conf` sets `PerSourcePenaltyExemptList 37.201.167.99` (owner's current IP) because sshd's per-source penalties locked out both the owner and the build connection. **Remove before the acceptance test.**
- 2026-10-24: Rename daemonia → daemonica applied on the VM via `/root/migrate.sh` (data directories moved, `daemonia-web` user replaced by `daemonica-web`, old package purged). Pre-migration backup: `/root/pre-rename-backup-20261024T2001.tgz`.

### Real-world setup on the VM (2026-10-24)

- Domain `daemonica.404squad.cloud:8443`, Let's Encrypt **production** certificate (owner approved, S2), HTTP-01 validated; allowlist = owner IP `37.201.167.99/32` (+ loopback).
- Owner completed the setup wizard in a real browser and registered the first admin passkey (account `pancake` → Linux user `pancake`, UID 1000). Login afterwards worked. Audit chain intact (27 records).
- Sessions are now persisted in the helper's accounts.db (since 19b8a5e); restarts no longer sign users out. Pre-migration DB backup verified (`backups/accounts.db.*.bak`).

### First install on the VM

- `.deb` installs, both services active, web listens on **127.0.0.1:8443 only** (not reachable on the public IP).
- `systemd-analyze security`: **daemonica-web 1.1** (target ≤ 2.0 ✓), **daemonica-helper 6.8** (target ≤ 6.0 ✖ — to be tightened).
- Bootstrap → token check → helper restart → audit chain verify: all ok. `govulncheck`: no vulnerabilities.
- Bug found and fixed: `/run/daemonica` was root:root 0750, so the web user could not reach `helper.sock` (fixed in d357a34).

### Milestones

| ID | Status | Notes |
|---|---|---|
| M1.0 | ⚠ nearly done | All core items done incl. accounts, audit view, allowlist Plan→Apply→Confirm. Open: TLS change in settings, DNS-01 guided, certificate renewal timer, Playwright E2E with virtual authenticator, helper hardening score ≤ 6.0. |
| M1.1 | ⚠ implemented, in owner test | Overview, services, logs, processes (see table below). Open: last logins, log follow via WebSocket (DEC-017), allowlisted log files (SOLL), owner acceptance check against `top`/`free`/`df`. |
| M1.2 – M1.8 | ✖ open | |

### M1.0 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| Repo layout, Makefile targets (`deps lint test test-integration test-e2e sec build package sbom release`) | ⚠ | Targets exist; `sbom`, `test-e2e` are stubs (tools unavailable). |
| Versioned, length-prefixed RPC, 1 MiB limit, strict decoding | ✓ | `internal/rpc`, tests + fuzz target |
| Helper on Unix sockets only; `helper.sock 0660 root:daemonica-web`, `admin.sock 0600` | ✓ | `internal/helper/server.go`; smoke test (socket modes verified) |
| `SO_PEERCRED` check | ✓ | `TestPeerCredOverRealSocket` |
| Typed op allowlist, no generic exec, channel separation | ✓ | `TestChannelSeparation` |
| Helper is trust anchor; grants resolved in helper; UID 0 mapping refused | ✓ | `grants.go`, `TestGrantRefusesRoot` |
| Policy table = Annex A, deny-by-default, generated matrix | ✓ | `internal/policy`, `TestGeneratedMatrix` |
| Step-up (5 min, fresh passkey ceremony verified in the helper, token rotation) enforced by helper | ✓ | `TestGrantAndStepUpEnforcement`, `TestSetupLoginStepUp` |
| Audit log JSONL + SHA-256 chain, verify, control-char stripping | ✓ | `internal/audit`; `daemonica-admin audit-verify` |
| Plan → Apply → Confirm with helper-side rollback timer, crash recovery journal | ✓ | `internal/planner` (handlers for network/firewall/allowlist follow) |
| Atomic config writes (temp + fsync + rename) | ✓ | `helper/config.go` |
| TLS 1.3 only, ECDSA P-256 | ✓ | `internal/tlsconf`, smoke test: TLS 1.2 refused |
| Allowlist at accept, before TLS; loopback default | ✓ | `internal/netallow`, `TestListenerDropsDisallowed` |
| Security headers / strict CSP, CSRF header + exact Origin, no CORS, RFC 9457 errors | ✓ | `internal/web/middleware*.go`, smoke test |
| Rate limits per IP + global, backoff, no account lockout | ✓ | `ratelimit.go` |
| Bootstrap token (256 bit, 60 min, one-time, hashed) | ✓ | `internal/auth`, persisted in accounts.db |
| Setup mode on 127.0.0.1 only | ✓ | smoke test: listener `127.0.0.1:8443` |
| WebAuthn enrollment / login / step-up (UV + resident key required, attestation none, exact origin, 120 s one-time challenges, clone detection) | ✓ | `internal/auth/passkey.go`; software-authenticator tests (`internal/testutil/softauthn`) incl. wrong origin, no-UV, replay, counter regression |
| Accounts DB (`accounts.db`, SQLite WAL, migrations with pre-backup), persistent one-time tokens | ✓ | `internal/store`, `helper/accounts.go` |
| Passkey management (list/add/rename/remove, last one protected, synced vs device-bound) | ✓ | API + UI `/security/passkeys` |
| Sessions persisted in helper DB (token hash only), survive restarts; rotation on step-up; session list + end session (own; admin: all) | ✓ | `TestSessionsPersistListAndRevoke`, UI `/security/sessions` |
| Accounts/roles management (invitations via one-time link, role change, disable, delete with type-name, last-admin and self-lockout protection, sessions ended on change) | ✓ | `helper/accountops.go`, `web/src/pages/Accounts.tsx`; tests `accountops_test.go` |
| Recovery (`daemonica-admin recover <account> [--revoke-all]`, ends sessions, 30 min token) | ✓ | `TestPasskeyManagementAndRecovery` |
| Setup wizard (token → domain → allowlist → certificate → switch to domain → first passkey), UI shell, dark (default)/light theme, de/en i18n, nav icons, mobile drawer | ✓ | Owner completed setup in a real browser on the VM (2026-10-24); headless Chromium: no CSP/Trusted-Types violations |
| Session cookie `__Host-`, Secure, HttpOnly, SameSite=Strict, rotation on login/step-up, grant never sent to browser | ✓ | `internal/web/auth_test.go` |
| ACME (Let's Encrypt, HTTP-01/TLS-ALPN-01, ECDSA P-256, staging/production) | ✓ (HTTP-01) / ✖ (DNS-01 guided, renewal timer, TLS change via settings) | Production cert issued for the test VM with owner approval (S2) |
| systemd units with hardening | ⚠ | Scores on the VM: daemonica-web **1.1** (target ≤ 2.0 ✓), daemonica-helper **6.8** (target ≤ 6.0 ✖, to tighten in M1.8) |
| `.deb` packaging, postinst/prerm/postrm | ✓ (install/upgrade on VM) / ⚠ (remove/purge test, arm64 install untested) | VM: install, reinstall and the daemonia→daemonica migration (data moved, accounts/passkeys/audit chain intact) |

### M1.1 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| Overview: hostname, OS/kernel, uptime, load, CPU, RAM/swap, mounts with usage + inodes, network interfaces with live throughput, top processes, reboot required, pending updates (total/security), failed units, dashboard certificate expiry, setup checklist | ✓ | `internal/sysinfo`, `helper/sysops.go`; integration test on the VM (`make test-integration`) |
| Last logins | ✖ | Ubuntu 26.04 uses wtmpdb; reader follows |
| One shared collector (3 s), no polling storm | ✓ | `sysinfo.Collector` in the helper; UI polls the cached snapshot |
| Services: list service/timer/socket with active/sub, autostart, since, memory; search + filter | ✓ | D-Bus (`internal/services`), integration test (295 units on the VM) |
| Actions start/stop/restart/reload/enable/disable/mask/unmask; detail: status, journal, unit file (read-only), dependencies | ✓ | `services.action`, UI drawer |
| Protected units (`daemonica-*`, ssh, `systemd-*`): admin + step-up + warning; helper not stoppable/disableable/maskable; web only with typed confirmation | ✓ | `TestServiceDecisionMatrix` |
| Logs: journald with unit/priority/time/boot filters, server-side search, follow, export TXT/JSON with line limit, control sequences neutralised | ✓ (follow via polling, DEC-017) | `internal/journal`, `TestArgsValidation`, `TestParseSanitisesAndCaps` |
| Processes: table (PID, user, CPU, RAM, start, command), sort/filter, signals TERM/KILL/HUP/STOP/CONT with confirmation; protected PID 1/daemonica/sshd; operator only own processes; PID-reuse guard | ✓ | `TestProcSignalRules` |
| Read-only role: no logs, no signals | ✓ | policy + UI hides log navigation |

### Test results

See the latest commit message and `make test` output. Coverage is reported by `make test`.
