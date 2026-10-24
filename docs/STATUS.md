# Status (progress against SPEC v1.2)

_Last updated: 2026-10-24_

## Current phase: Phase 1 — milestone M1.0 (in progress)

### Blockers (need owner action)

| # | Blocker | SPEC | Needed from owner |
|---|---|---|---|
| B1 | **Test VM access** missing. | S2, §6.1 | Fill in `test_vm.md` (local, git-ignored) and provide an SSH key for the VM separately. |
| B2 | **Package registries blocked** in the build environment: `proxy.golang.org`, `sum.golang.org`, `registry.npmjs.org`, `gitlab.com`, `go.googlesource.com`. Without them neither WebAuthn/SQLite/PTY/WebSocket libraries nor the React frontend can be built in a verifiable way (DEC-002). | §4.1, §4.4, D-01 | Allow these domains for Claude (claude.ai → Settings → Capabilities, or org admin), **or** build on the test VM once B1 is solved. |
| B3 | **Push to GitHub refused**: the Claude GitHub App has no write access to `PanPakaPancake/daemonica`. Commits exist locally only. | — | Install the Claude GitHub App for the repo or reconnect GitHub in claude.ai settings. |
| B4 | Go toolchain 1.24.7 (likely out of upstream support), newer toolchain not downloadable (DEC-003). | §4.1 | Resolved together with B2. |
| B5 | Branding assets (`daemonia-logo-transparent.png`, `daemonia-mascot.png`) not in the repository. | §5.4 | Add the two PNGs to `assets/branding/`. |
| B6 | Package signing key. | S2, §4.3 | Later (release candidate); until then artifacts are `-UNSIGNED-TESTONLY`. |

### Test VM

Not yet accessed (B1). Planned first actions: `/etc/os-release`, resources, network, snapshot capability → recorded here.

### Milestones

| ID | Status | Notes |
|---|---|---|
| M1.0 | ⚠ in progress | Stdlib foundation done (see table). WebAuthn, account DB, React UI blocked by B2. |
| M1.1 – M1.8 | ✖ open | |

### M1.0 requirement status

| Requirement | Status | Evidence |
|---|---|---|
| Repo layout, Makefile targets (`deps lint test test-integration test-e2e sec build package sbom release`) | ⚠ | Targets exist; `sbom`, `test-e2e` are stubs (tools unavailable). |
| Versioned, length-prefixed RPC, 1 MiB limit, strict decoding | ✓ | `internal/rpc`, tests + fuzz target |
| Helper on Unix sockets only; `helper.sock 0660 root:daemonia-web`, `admin.sock 0600` | ✓ | `internal/helper/server.go`; smoke test (socket modes verified) |
| `SO_PEERCRED` check | ✓ | `TestPeerCredOverRealSocket` |
| Typed op allowlist, no generic exec, channel separation | ✓ | `TestChannelSeparation` |
| Helper is trust anchor; grants resolved in helper; UID 0 mapping refused | ✓ | `grants.go`, `TestGrantRefusesRoot` |
| Policy table = Annex A, deny-by-default, generated matrix | ✓ | `internal/policy`, `TestGeneratedMatrix` |
| Step-up (5 min) enforced by helper | ✓ (state model) / ✖ (WebAuthn ceremony) | `TestGrantAndStepUpEnforcement` |
| Audit log JSONL + SHA-256 chain, verify, control-char stripping | ✓ | `internal/audit`; `daemonia-admin audit-verify` |
| Plan → Apply → Confirm with helper-side rollback timer, crash recovery journal | ✓ | `internal/planner` (handlers for network/firewall/allowlist follow) |
| Atomic config writes (temp + fsync + rename) | ✓ | `helper/config.go` |
| TLS 1.3 only, ECDSA P-256 | ✓ | `internal/tlsconf`, smoke test: TLS 1.2 refused |
| Allowlist at accept, before TLS; loopback default | ✓ | `internal/netallow`, `TestListenerDropsDisallowed` |
| Security headers / strict CSP, CSRF header + exact Origin, no CORS, RFC 9457 errors | ✓ | `internal/web/middleware*.go`, smoke test |
| Rate limits per IP + global, backoff, no account lockout | ✓ | `ratelimit.go` |
| Bootstrap token (256 bit, 60 min, one-time, hashed) | ✓ (in memory) | `internal/auth`; persists in accounts.db once SQLite is available |
| Setup mode on 127.0.0.1 only | ✓ | smoke test: listener `127.0.0.1:8443` |
| WebAuthn enrollment / login / step-up | ✖ | B2 |
| Accounts DB (`accounts.db`, SQLite), accounts/roles/passkeys/sessions UI | ✖ | B2 |
| Recovery (`daemonia-admin recover`) | ✖ | depends on accounts DB |
| Setup wizard, UI shell, theme, i18n, branding | ✖ | B2, B5 (placeholder page embedded) |
| systemd units with hardening | ⚠ | Written; `systemd-analyze security` scores pending (B1) |
| `.deb` packaging, postinst/prerm/postrm | ⚠ | `scripts/build-deb.sh`; install test pending (B1) |

### Test results

See the latest commit message and `make test` output. Coverage is reported by `make test`.
