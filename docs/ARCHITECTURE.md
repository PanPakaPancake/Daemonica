# Architecture

Daemonica manages exactly one Debian/Ubuntu host. It is split into three binaries
(SPEC §3.2):

```
 Browser ──TLS 1.3──▶ daemonica-web (user daemonica-web, no capabilities)
                        │  allowlist check at accept() → TLS → CSP/CSRF/session middleware
                        │  opaque grant token per session
                        ▼
              /run/daemonica/helper.sock (0660 root:daemonica-web, SO_PEERCRED = daemonica-web)
                        ▼
                 daemonica-helper (root) ── typed op allowlist ── policy (Annex A) ── audit chain
                        ▲
              /run/daemonica/admin.sock (0600 root, SO_PEERCRED = 0)
                        │
                 daemonica-admin (root CLI: bootstrap, recover, allowlist-reset, audit-verify…)
```

## Packages

| Package | Responsibility |
|---|---|
| `internal/rpc` | Wire protocol: 4-byte length + strict JSON, version 1, max 1 MiB; client. |
| `internal/helper` | Socket servers, peer-credential check, op registry, dispatch (authn → authz → execute → audit), grants, config store, core ops. |
| `internal/policy` | Annex A as a table; `Decide()`; deny by default. |
| `internal/audit` | JSONL audit log with SHA-256 hash chain, verification, ULIDs. |
| `internal/auth` | One-time tokens (bootstrap/recovery/invite), hashing, lifetimes. WebAuthn ceremonies will live here (verified in the helper). |
| `internal/planner` | Plan → Apply → Confirm with helper-side rollback timer and crash-recovery journal. |
| `internal/netallow` | CIDR allowlist, accept-time enforcement. |
| `internal/tlsconf` | TLS 1.3-only config, hot-swappable certificate, setup certificate, operator certificate checks. |
| `internal/validate` | Strict allowlist validators for identifiers passed to programs/files. |
| `internal/web` | HTTP handlers, middleware (headers, CSRF, problem+json, correlation ID, panic recovery), rate limiter. |
| `internal/web/ui` | Embedded frontend build (`go:embed`). |
| `internal/worker` | Re-exec of the helper binary under a Linux user's credentials (`no_new_privs`, umask 077); optional data pipe on fd 3 for streams. |
| `internal/sysinfo`, `internal/services`, `internal/journal`, `internal/execx` | M1.1 data sources: `/proc` collector, systemd over D-Bus, `journalctl --output=json`, bounded argv execution. |
| `internal/users`, `internal/sshkeys` | M1.2: shadow-utils via argv, `authorized_keys` parser and worker handlers. |
| `internal/files` | M1.3 file manager worker operations (openat2-based path handling, rules on canonical paths, streams; DEC-019). |

## Request flow (authenticated operation)

1. TCP accept → `netallow.Listener` drops non-allowlisted peers (RST) before TLS.
2. TLS 1.3 handshake.
3. Middleware: panic recovery → correlation ID → security headers → CSRF (header + Origin) → route.
4. Handler resolves the session cookie to a grant token (web.db) and calls the helper.
5. Helper: decode strictly → op exists on this channel? → resolve grant (idle/absolute expiry) → `policy.Decide` → handler with timeout → audit record (also on deny/error).

## Helper operations implemented (M1.0 so far)

| Op | Channel | Auth | Purpose |
|---|---|---|---|
| `admin.status` | admin | root | State overview |
| `admin.bootstrap` | admin | root | Issue setup token, optional allowlist entries |
| `admin.allowlist_reset` | admin | root | Emergency: loopback-only allowlist |
| `admin.audit_verify` | admin | root | Verify hash chain |
| `setup.state` | web | pre-auth | Setup mode flag, default language |
| `setup.check_token` | web | pre-auth | Validate bootstrap token (rate-limited in web) |
| `config.web` | web | pre-auth (socket-local only) | Listener settings |
| `session.whoami` | web | grant | Current subject |

## Helper operations (M1.1–M1.3)

| Namespace | Operations | Policy action(s) |
|---|---|---|
| `sysinfo` / `proc` | `sysinfo.overview`, `proc.list`, `proc.signal` | overview.read, proc.read, proc.signal (owner check) |
| `services` | `services.list`, `services.get`, `services.action` | overview.read; services.control / control_protected / enable (decided per unit and action) |
| `journal` | `journal.query` | logs.read |
| `users` / `groups` | `users.list/create/update/set_locked/set_sudo/set_password/delete`, `groups.create/set_members/delete` | users.read, users.write |
| `sshkeys` | `sshkeys.list/add/remove/set_options/fix_permissions/server` | sshkeys.own, sshkeys.others |
| `fs` | `fs.info`, `fs.list`, `fs.stat`, `fs.create`, `fs.rename`, `fs.transfer`, `fs.delete`, `fs.chmod`, `fs.chown` (root mode only), `fs.download_token`, `fs.root_enable` (step-up), `fs.root_disable`; streams: `fs.read`, `fs.write`, `fs.upload`, `fs.download` | files, files.root |

### Streams

Streaming operations (uploads/downloads) use the same request frame, then a
"ready" response frame, then length-prefixed chunks (≤ 256 KiB) ending with a
zero-length end marker, then a final response frame (`internal/rpc/stream.go`).
A stream without end marker is an abort. Every read/write refreshes a 2-minute
idle deadline, so long transfers work while stalled peers are dropped. In the
helper, stream data is piped to/from the worker's fd 3 using the same framing,
so the worker can tell a completed upload from an aborted one.

## Hardening exceptions (daemonica-helper.service)

| Directive not set | Reason |
|---|---|
| `NoNewPrivileges=yes` | The elevated terminal must run `sudo` (SPEC §3.9); standard workers set `no_new_privs` themselves. |
| `ProtectSystem=strict` / `ProtectHome=yes` | The helper edits system configuration (users, network, fstab, apt) and home directories (`authorized_keys`, file manager). |
| `PrivateDevices=yes` | Mount/unmount and disk inventory need block devices. |
| `ProtectKernelTunables=yes` | Network configuration and later checklist fixes write sysctls. |
| `ProtectHostname=yes` | Hostname changes (M1.7). |
| `CapabilityBoundingSet=` restriction | Root operations across many subsystems; to be narrowed per milestone with measured needs. |
| `RestrictNamespaces=yes` (fully) | Transient units / container management (Phase 3) need namespaces; only user namespaces are denied. |
| `MemoryDenyWriteExecute=yes` | Child programs (apt, dpkg maintainer scripts) may need W+X mappings. |
| `RestrictSUIDSGID=yes` | `sudo`/setuid programs in the elevated terminal. |
| `ProtectProc=invisible` | Process management needs all processes. |
| `PrivateTmp=yes` | File manager workers (and later terminals) inherit the helper's mount namespace and must see the real `/tmp` (DEC-019). |

Actual `systemd-analyze security` scores will be recorded in the phase audit report.
