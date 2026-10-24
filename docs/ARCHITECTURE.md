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

Actual `systemd-analyze security` scores will be recorded in the phase audit report.
