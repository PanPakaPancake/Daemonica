# Status (progress against SPEC v1.2)

_Last updated: 2026-10-25_

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

- 2026-10-24: `/etc/ssh/sshd_config.d/90-daemonica-dev.conf` sets `PerSourcePenaltyExemptList 37.201.167.99` (owner's current IP) because sshd's per-source penalties locked out both the owner and the build connection. Removed 2026-10-25 after the M1.5 acceptance (owner OK).
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
| M1.2 | ⚠ implemented, in owner test | Users/groups and SSH keys (table below). Open: last login per user (wtmpdb), owner acceptance. |
| M1.3 | ✓ accepted by owner 2026-10-25 | File manager, editor, up/download (table below). SOLL items /etc pre-versions and validators done (DEC-021); lists with sort/filter on every column and right-click menus (DEC-022). Open: folder download as archive (KANN). |
| M1.4 | ✓ accepted by owner 2026-10-25 | Web terminal (table below, DEC-023). KANN items (keep background processes, reconnect after short drops) not implemented. |
| M1.5 | ✓ accepted by owner 2026-10-25 | Network, firewall, firewall logs, packet capture (tables below, DEC-024–DEC-028). Browser acceptance 1–4 passed on the VM 2026-10-25. |
| M1.6 | ✓ accepted by the owner (2026-10-25) | Tasks and jobs plus script library and cron schedule builder (table below, DEC-029, DEC-030). |
| M1.7 – M1.8 | ✖ open | |

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

### M1.2 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| Linux users: UID, name, description, home, shell, groups, locked, password age/expiry, SSH key count; system vs. regular via `UID_MIN/UID_MAX`; groups with members | ✓ | `internal/users`, UI `/users` |
| Create (validated name, home, shell from `/etc/shells`, groups; password locked by default), edit (shell, description, groups, expiry), lock/unlock (also expires the account so keys stop working), delete with/without home ("type name"), groups create/members/delete | ✓ | `helper/userops.go`; `TestUserOpsCommands`; host test creates/locks/deletes a real user |
| sudo membership visible and changeable with warning; step-up for all changes | ✓ | `users.set_sudo`, Annex A `users.write` (S) |
| Password via `chpasswd` stdin only, min. 12 chars, strength hint, force change at next login | ✓ | `TestUserOpsCommands` (stdin checked, never argv) |
| Protections: root not deletable/lockable; users mapped to an active dashboard admin need extra confirmation; system users only in advanced mode | ✓ | `TestUserOpsProtections` |
| Shadow-utils via argv with `--` before names, no direct /etc/passwd edits | ✓ | `helper/userops.go` |
| SSH keys per user from `AuthorizedKeysFile` (`sshd -T`), type, bits, SHA256 fingerprint, comment, options | ✓ | `internal/sshkeys` |
| Add with parser validation (ed25519, sk-*, ecdsa, RSA ≥ 3072; dss/short RSA rejected), remove, guided options (`from=`, `restrict`, `no-*`, `command=` with warning) | ✓ | `TestParseRejects`, `TestOptions`, fuzz target |
| Permission check/repair (`~/.ssh 0700`, file `0600`, owner) | ✓ | host test breaks and repairs permissions |
| Key files read/written by a worker under the user's credentials (`no_new_privs`), atomic write, optimistic concurrency, symlinks not followed | ✓ | `internal/worker`, host test: symlink to `/etc/shadow` refused, shadow untouched |
| Host keys with fingerprints; effective `sshd -T` read-only | ✓ | `sshkeys.server` |
| Operator manages own keys only; admin all (step-up for others) | ✓ | `SSHKeyOps.target` |

### M1.3 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| View: tree + list, breadcrumbs, sort/filter, search in folder, properties (owner, group, rwx + octal, size, times, symlink target), hidden files toggle, server-side pagination | ✓ | `files.List/Stat`, UI `/files`; `TestListSortFilterPage` |
| Views details/compact/tiles (remembered per browser); sortable column headers (name, type, size, mode, owner, modified) and filter row for every column (name, type, size, mode, owner, modified), server-side; right-click menu | ✓ | DEC-022; `files.ListArgs` `owner`/`kind`/`size`/`mode`/`mtime`, sort `mode`/`owner`; `TestListSortFilterPage`, `TestParseNumFilter`, `TestModeMatches` |
| New file/folder, rename, move/copy (cross-device move = copy + delete), delete (recursive only with typed name), chmod (Linux rules), chown (admin + step-up root mode only) | ✓ | `internal/files`; `TestCreateRenameRawDelete`, `TestTransfer`; `TestFileManagerEndToEnd` |
| All operations in a worker under the mapped Linux user; Linux permissions are the boundary | ✓ | integration: create in `/etc` → `permission_denied`, upload owned by the user |
| Root mode: admin only, step-up, 10 min, red bar, every write audited | ✓ | `fs.root_enable` (files.root, step-up), session-bound; `RootBar`; integration test |
| Hard-blocked Daemonica data/keys/sockets (also as root); access attempts denied and audited | ✓ | `files.Blocked` on canonical paths; `TestRulesOnCanonicalPath`; denied results audited |
| Sensitive paths (shadow, gshadow, host keys, `~/.ssh/id_*`): warning confirmation + step-up | ✓ | `useFsRunner` dialog; helper permit; integration test |
| Path safety: canonicalization, no NUL, fd-based (`openat2`, `RESOLVE_*`), no symlink following on writes, TOCTOU race test | ✓ | DEC-019; `TestWriteSymlinkedDirRefused`, `TestSymlinkRaceRootMode` |
| Editor: CodeMirror 6, highlighting (conf/ini/yaml/json/toml/sh/py/js/ts/md/sql/xml/nginx/systemd/crontab …), search/replace, line numbers, wrap, indentation, LF/CRLF kept, UTF-8 only, binary → download, 5 MiB limit | ✓ | `CodeEditor.tsx`, `files.Read` (binary/size detection) |
| Save atomic (temp + rename) keeping owner/mode/ACL/xattr; optimistic concurrency with diff dialog; unsaved-changes warning; clear read-only message | ✓ | `files.Write`; `TestEditorRoundTrip`; `FileEditor.tsx` |
| /etc pre-versions (30 days/20 versions) with restore | ✓ | DEC-021; `VersionStore`, `fs.versions`/`fs.version_read`, editor „Versionen“; `TestSaveKeepsPreviousVersion`, `TestVersionStoreRetention` |
| Validation of known files before saving (sshd, sudoers, nginx, units, fstab) | ✓ | DEC-021; sudoers blocking pre-check, others post-check with rollback; `TestSave*`, `TestValidatorFor`; integration `TestEditorValidationAndVersions` with real `sshd -t`, `nginx -t`, `visudo -c` |
| Upload: drag & drop, multiple, progress, cancel, streaming, limit (default 1 GiB), space check, mode 0640 (changeable), owner = user, overwrite only after confirmation, SHA-256 in audit | ✓ | `files.Upload`, `useUploads`; `TestUpload`, `TestLargeUploadStreams` (512 MiB, heap < 64 MiB) |
| Download: streaming with Range, `attachment` + `nosniff`, one-time token (60 s) | ✓ | `fileDownload`, `fs.download_token`; integration test (reuse/other session refused) |
| Roles: read-only ✖; operator/admin within Linux permissions | ✓ | policy `files` (read-only deny), UI hides navigation |

### M1.4 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| xterm.js, PTY, WebSocket with ticket and origin check | ✓ | `pty.open` duplex stream, `/api/v1/terminal/ticket` + `/ws`; `TestTerminalSocket*` |
| Tabs (max. 5 per account), resize, copy/paste (bracketed paste), scrollback search, UTF-8, `TERM=xterm-256color`, login shell | ✓ | `Terminal.tsx`, `terminals.tsx`; `TestTerminalLimitPerAccount`, `TestTerminalStandardShell` |
| Standard shell with `no_new_privs` (sudo/su/setuid without effect) | ✓ | `NoNewPrivileges=yes` on the unit; `TestExecShellNoNewPrivs`, integration `TestTerminalOnHost` |
| Elevated mode (admin, step-up on every opening): root shell or user shell with sudo; red "ERHÖHT" bar; 30 min maximum | ✓ | `TestTerminalElevatedNeedsFreshStepUp`, `TestTerminalReadOnlyDenied`; UI bars |
| Idle timeout 15 min (configurable); end on logout, role change, lock, allowlist change | ✓ | `TestTerminalEndsWithSessionAndIdle`, `TestTerminalCutWhenAllowlistChanges`; web re-check of the allowlist |
| Transient unit with `TasksMax`/`MemoryMax`; session end kills the process tree (SIGHUP, SIGKILL after 5 s) (SOLL) | ✓ | `SystemdLauncher`; `TestStopKillsProcessTree`, `TestSystemdLauncherLifecycle`, `TestTerminalOnHost` |
| Throughput limit | ✓ | output 4 MiB/s, input 256 KiB/s, 64 KiB per message |
| Audit start/end, mode, duration, source IP (no input) | ✓ | `pty.start`, `pty.open` (`end`, `duration_s`); `TestTerminalStandardShell` |
| No file transfer; read-only ✖ | ✓ | no transfer protocol; policy `terminal` denies read-only |
| Keep background processes, reconnect after short drops (KANN) | ✖ | not implemented |

### M1.5 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| Detect netplan (incl. renderer), ifupdown, NetworkManager, systemd-networkd; mixed/unsupported read-only with explanation | ✓ | `netcfg.Detector`; `TestDetectAndDNS` |
| Writing for netplan and ifupdown (MUSS) | ✓ | `TestNetplanReadEdit`, `TestNetplanNewAndConflicts`, `TestIfupdown`, `TestNetplanGenerateReal` |
| Writing for NetworkManager and systemd-networkd (SOLL) | ✖ | read-only (DEC-024) |
| Interfaces, routes, DNS, gateway, hostname, open ports with process | ✓ | `net.get`, `net.ports`; integration test compares with `ss` |
| DHCP/static v4/v6, gateway, DNS, MTU, extra addresses, static routes; VLAN/bridge/bond shown | ✓ | `Network.tsx`; `TestNormalize` |
| Plan → Apply → Confirm, 90 s rollback in the helper, confirm over a new connection, red warning for the session's interface/route, diff, syntax check, change lock | ✓ | `TestNetworkPlanApplyRollback`, `TestNetworkHandlerVerifiesKernelState`; integration `TestLauncherUmaskNetplan`; VM test "wrong gateway rolls back" passed 2026-10-25 (first run failed: netplan under UMask=0077, fixed in 93ace59) |
| Firewall status: backend, active, persistent, defaults, rule count, IPv6, logging, last change from audit, counters; traffic light with plain-language hints | ✓ | `firewall.get`; `TestLight`, `TestCounters`, `TestFirewallPlanEnable` |
| Reachability view (SOLL) | ✓ | `Reach` tab; `TestEvaluate` |
| ufw rules with explanations, managed-rule marking, add (template or port/protocol, source, allow/deny/limit), delete, logging level, enable/disable | ✓ | `Firewall.tsx`, `explainRule` tests, `TestPlanSimulateSteps`, `TestAddSpec` |
| Raw view (`nft list ruleset` / `iptables-save`), searchable, export; firewalld read-only | ✓ | `firewall.raw`; `TestDetect` |
| Auto rules for SSH (`sshd -T`) and dashboard on enable, mandatory acknowledgement, timer; reset with step-up + type name | ✓ | `TestAccessRules`, `TestFirewallPlanEnable` |
| Install ufw when missing | ✓ | `firewall.install` |
| All firewall changes via Plan → Apply → Confirm with lockout protection | ✓ | `TestHandlerApplyRollback`; VM test "enable does not lock out" passed 2026-10-25 |
| Firewall logs: journald kernel entries parsed into fields, filters, free text, live follow over WebSocket with rate limit and skipped hint | ✓ | `TestParseLog`, `TestFirewallLogsAndBlockSource`, `TestFollowSocket`; VM test "< 3 s" passed 2026-10-25 |
| Export CSV/JSON with row limit | ✓ | 2000 rows per query (DEC-027) |
| Statistics (SOLL): top sources, top ports, timeline, per action | ✓ | `FirewallLogs.tsx` |
| Block source (admin, step-up, plan) with protection of own IP, allowlist networks, SSH/dashboard | ✓ | `TestFirewallLogsAndBlockSource` |
| Logging control with explanations, wizard when off, warning for high/full | ✓ | `FirewallLogs.tsx`, `Firewall.tsx` |
| Entries lost to journald rate limiting shown "as far as detectable" | ✖ | not implemented yet |
| No external lookups; only parsed fields shown | ✓ | DEC-027 |
| Packet capture: admin only, step-up per start, privacy warning, audit without contents | ✓ | `TestCaptureOps`, policy table |
| Wizard: purpose templates, interface (regex + existence), filter builder, free BPF under Advanced (allowlist, no leading `-`, compile check, single argv element), limits, full packets with extra warning, promiscuous off, dashboard excluded | ✓ | `capture.Spec`, `TestSpec`, `TestCaptureOps`, `Capture.tsx`, `capture.test.ts` |
| tcpdump in a transient unit with `CAP_NET_RAW` only, `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `RestrictAddressFamilies`, `SystemCallFilter`, `MemoryMax`, `RuntimeMaxSec` | ✓ | `TestUnitProperties`; integration `TestCaptureOnHost` checks `systemctl show`, UID, CapEff and NoNewPrivs on the VM (passed 2026-10-25) |
| Helper enforces duration, packets, size, free disk; one capture at a time | ✓ | manager tests |
| Own memory-safe parser for the live summary (Ethernet/VLAN, ARP, IPv4/6, TCP/UDP/ICMP(v6), DNS names) | ✓ | `FuzzSummarize` |
| Live view over WebSocket (500 lines/s, "N packets not shown"), pause, view filter, client buffer 10,000; statistics (SOLL) | ✓ | `Capture.tsx`, DEC-026 |
| Storage 0600, retention 24 h (1–168 h), total limit 1 GiB, delete all; download as attachment via 60 s one-time token with step-up | ✓ | `TestCaptureOps`, manager prune test; metadata as JSON sidecars (DEC-028) |
| Install tcpdump when missing (admin, step-up) | ✓ | `capture.install` |

### M1.6 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| Overview: systemd timers (unit, next/last run, result) | ✓ | `services.Timers`; Jobs page tab "systemd timers" |
| Overview: cron (`/etc/crontab`, `/etc/cron.d`, `cron.{hourly,daily,weekly,monthly}`, user crontabs) | ✓ | `jobs.Cron`; `TestCronFiles` |
| `at` jobs (KANN) | ✖ | not implemented |
| Managed jobs as service + timer `daemonica-job-*` in `/etc/systemd/system`, metadata in the helper | ✓ | `jobs.Manager`; `TestManagerLifecycle` |
| Wizard: name/description, command as program + arguments or script, shell only under "advanced" with warning | ✓ | `Jobs.tsx`; `TestNormalize` |
| User: default the mapped user, others admin only, root admin + step-up | ✓ | `TestJobOpsRoles` |
| Schedule builder (hourly/daily/weekly/monthly/interval/calendar), plain-language preview, next 5 runs via `systemd-analyze calendar`, time zone, `Persistent`, `RandomizedDelaySec` | ✓ | `TestOnCalendar`, `TestParseAnalyze`, `TestNextRunsRealSystemd` |
| Timeout (default 1 h), environment, working directory, "standard secure" hardening with writable paths, resource limits | ✓ | `TestUnitModesAndTimer`, `TestUnitInjection` |
| Output to journald; actions run now, enable/disable, edit, duplicate, delete; history of the last 20 runs (start, duration, exit code, journal excerpt) | ✓ | `TestParseHistory`, `Jobs.tsx` |
| Cron (SOLL): create/edit/delete user crontab entries with syntax check and next runs; the same schedule builder as the jobs (hourly to interval, at boot, own expression) | ✓ | `TestCronExpr`, `TestCronFiles`, `cron.save`, `cron.test.ts` |
| "Convert to systemd timer" (KANN) | ✖ | not implemented |
| Security: commands never in the web process; unit names allowlisted; unit-file injection (line breaks, `%` specifiers) masked; arguments not interpreted by a shell | ✓ | DEC-029; `TestUnitInjection`; programs must be trusted files (`TestTrusted`) |
| Roles: operator runs and enables/disables; admin everything; read-only views | ✓ | policy table; `TestJobOpsRoles` |
| Acceptance: job runs at the scheduled time, history shows exit code and log; injection payloads without effect; hardening visible in `systemctl show` | ✓ | integration `TestJobsOnHost`; scheduled run in the browser acceptance |
| Script library (Timo's request, not in the SPEC; DEC-030): local scripts with editor, GitHub collections pinned to a commit, update only after diff + step-up, use as job or in the terminal, audit | ✓ | `TestLibraryLifecycle`, `TestParseTarball`, `TestGitHub`, `TestScriptOpsRoles`; `Scripts.tsx` |
| Script library on the host: readable for other users despite umask 0077, trusted for root jobs, runs as `nobody`, real GitHub download | ✓ | integration `TestScriptLibraryOnHost` |

### Test results

See the latest commit message and `make test` output. Coverage is reported by `make test`.
