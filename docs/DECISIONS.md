# Decisions (ADR log)

Format per SPEC §0.3: ID, date, context, decision, rejected alternatives, security assessment.

---

## DEC-001 — Repository name vs. product name
- **Date:** 2026-10-24
- **Context:** The owner created the repository `PanPakaPancake/Daemonica`; the SPEC names the product **Daemonia** (A-01).
- **Decision:** Product, binaries, package and UI use **Daemonia** as specified. The Go module path follows the repository: `github.com/PanPakaPancake/daemonica`.
- **Rejected:** Renaming the product to "Daemonica" (contradicts A-01 and the logo).
- **Security:** none.

## DEC-002 — Build environment egress restrictions (blocker)
- **Date:** 2026-10-24
- **Context:** The build sandbox has no access to `proxy.golang.org`, `sum.golang.org`, `registry.npmjs.org`, `gitlab.com` (modernc.org/sqlite) or `go.googlesource.com` (golang.org/x/*). Only GitHub is reachable.
- **Decision:** Implement the M1.0 foundation **with the Go standard library only** until access is granted. Third-party dependencies (go-webauthn, modernc sqlite, creack/pty, websocket, lego) and the entire React frontend are deferred. No dependency is fetched while checksum-database verification is impossible, and `GOSUMDB=off`/`GOFLAGS=-insecure` are **not** used.
- **Rejected:** (a) Fetching modules directly from GitHub with `GOSUMDB=off` — weakens supply-chain verification (SPEC §4.4, A4) → S3 territory. (b) Vendoring hand-copied sources — unverifiable provenance (D-19). (c) Replacing React with a hand-written vanilla UI — violates D-01.
- **Security:** Conservative; no unverified code enters the build. Owner action needed: allow the registries (see STATUS.md "Blocker").

## DEC-003 — Go toolchain version
- **Date:** 2026-10-24
- **Context:** SPEC §4.1 asks for the current stable Go at project start; only Go 1.24.7 is installed and toolchain downloads are blocked (DEC-002).
- **Decision:** `go 1.24.7` in `go.mod` for now. Will be raised to the current stable release (with a `toolchain` line) once `proxy.golang.org` is reachable.
- **Security:** Go supports only the two most recent minor releases; 1.24 is very likely **out of upstream support** by now. This is a known gap (not acceptable for a release), tracked as blocker in STATUS.md and to be fixed before any release candidate.

## DEC-004 — Helper-owned configuration file
- **Date:** 2026-10-24
- **Context:** Security-relevant settings (domain, port, allowlist, session bounds, setup state) must be controlled by the trust anchor (SPEC §3.2 rule 3) and readable before the account DB exists.
- **Decision:** `/var/lib/daemonia-helper/config.json` (root 0600), written atomically (temp + fsync + rename + dir fsync), validated on load and on every update. The web process receives a read-only subset via the `config.web` RPC.
- **Rejected:** Storing settings in `web.db` (web process could alter its own allowlist after compromise, A3).
- **Security:** Improves A3 resistance: a compromised web process cannot widen the allowlist.

## DEC-005 — RPC framing and grants
- **Date:** 2026-10-24
- **Decision:** 4-byte big-endian length + strict JSON (unknown fields rejected), protocol version 1, max 1 MiB. Operation names restricted by regex. The web process passes an opaque **grant token**; the helper stores only its SHA-256 hash and resolves account, role, Linux user and step-up itself. One connection per call (simplicity, failure isolation).
- **Rejected:** gRPC/protobuf (extra dependency, larger attack surface); HMAC-signed self-contained grants (revocation harder).
- **Security:** Web cannot assert roles (SPEC §3.2 rule 4). Grants issued only for UID ≠ 0.

## DEC-006 — Audit log mirror
- **Date:** 2026-10-24
- **Decision:** Each audit record is fsynced to `/var/log/daemonia/audit.log` and mirrored as a JSON line to stdout of the helper (journald, `SyslogIdentifier=daemonia-helper`). A dedicated `daemonia-audit` identifier requires native journald protocol support and is planned with the journal module (M1.1).
- **Security:** Records strip control characters (log forging). `chattr +a` is applied by the package in a later milestone (SOLL).

## DEC-007 — Bootstrap allowlist suggestion
- **Date:** 2026-10-24
- **Context:** SPEC §3.3 asks to suggest "the current client network" from `SSH_CLIENT`.
- **Decision:** Suggest the exact IPv4 address (/32) or the IPv6 /64 (privacy extensions rotate the host part). Never applied automatically; the admin must pass `--allow`. Public prefixes (< /8 v4, < /7 v6) are refused during bootstrap.
- **Security:** Most restrictive sensible default (D-05).

## DEC-008 — Allowlist-reject handling
- **Date:** 2026-10-24
- **Decision:** Disallowed TCP peers are closed with `SO_LINGER=0` (RST) immediately after `accept`, before any TLS bytes are read. Rejections are not logged per connection (log-flood DoS); an aggregated counter follows with the metrics collector.

## DEC-009 — Target matrix (preliminary)
- **Date:** 2026-10-24
- **Context:** SPEC §6.1: supported Debian and Ubuntu LTS releases at project start. The owner's test VM runs **Ubuntu 26.04 LTS**.
- **Decision (preliminary, to be confirmed by research once web access for this is used):** Ubuntu 26.04 LTS (primary, test VM), Ubuntu 24.04 LTS, Debian 13 "trixie", Debian 12 "bookworm" (while in LTS). Testing: Ubuntu 26.04 on the VM; others via containers where possible.
- **Security:** none.

## DEC-010 — Setup-mode certificate and origins
- **Date:** 2026-10-24
- **Decision:** In setup mode the web process binds only `127.0.0.1:<port>` and uses an in-memory, self-signed ECDSA P-256 certificate (24 h, never persisted). Accepted origins: `https://localhost:<port>` and `https://127.0.0.1:<port>` (SSH tunnel). After setup only `https://<domain>:<port>` is accepted.
- **Security:** Browser shows a certificate warning in setup mode only; access requires SSH + bootstrap token.

## DEC-011 — Build on the test VM
- **Date:** 2026-10-24
- **Context:** The cloud build environment cannot reach Go/npm registries (DEC-002); the test VM can.
- **Decision:** Builds, dependency resolution (with `sum.golang.org` verification and `npm ci --ignore-scripts`) and all tests run on the test VM. Go is installed from the official go.dev tarball, verified against the SHA-256 published in go.dev's release index; Node/npm from the Ubuntu archive (D-19).
- **Security:** Full checksum-database verification restored; supersedes the stdlib-only restriction of DEC-002.
