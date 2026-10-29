# Security audit — Phase 1

SPEC §6.5 (D-11). Scope: everything delivered in Phase 1 (M1.0 – M1.8), branch `wip/m18`.
Date: 2026-10-29. Auditor: Claude (AI review per catalogue SA-01 … SA-15 plus automatic tools).

Sequence: (1) automatic tools, (2) AI review per catalogue, (3) this report, (4) fixes, (5) re-test.
Rows marked **VM** are re-tested in the full test on the freshly installed VM (M1.8 step 6) and filled in there.

## Summary

| Severity | Found | Fixed | Decision needed | Backlog |
|---|---|---|---|---|
| Critical | 0 | – | – | – |
| High | 0 | – | – | – |
| Medium | 3 | 3 | 0 | – |
| Low | 5 | 3 | – | 2 |
| Info | 5 | 3 | – | 2 |

No finding needs a risk decision by the owner at this point. Gate rule (SPEC §6.5): met in the build environment; the VM re-test is still open.

## 1. Automatic tools

| Tool | Version | Result | Notes |
|---|---|---|---|
| `go vet` (+ `-tags integration`) | Go 1.27.3 | clean | |
| `staticcheck` | 2026.2.2 | clean after fixes (F-05) | first run: 12 findings (unused code, deprecated APIs, U+202E literal) |
| `golangci-lint` | 2.15.0 | clean | `.golangci.yml`: default linters + `gosec`; only `QF1001` (De Morgan style) and naming/doc style checks off |
| `gosec` (through golangci-lint) | – | clean | 23 findings in production code, each reviewed and annotated with the reason (F-04); standalone `gosec` raw: 101 incl. tests |
| `govulncheck` | 1.9.0 | **0 reachable** vulnerabilities | run with `-db file://` from `golang/vulndb` (data as of 2026-10-27), as `vuln.go.dev` is not reachable from the build environment; 7 unreached findings in `golang.org/x/net` 0.59.0 fixed by upgrading (F-03); `x/crypto/openpgp` (unmaintained, not imported) remains as info |
| `osv-scanner` | 2.7.0 | **VM** | `api.osv.dev` refused from the build environment (F-10) |
| `gitleaks git` (all 98 commits) | 8.x | clean | 2 reviewed false positives in `.gitleaksignore` (F-06) |
| `scripts/check-secrets.sh` | – | clean | failed before on a test fixture header line (F-06) |
| `npm audit --omit=dev` | npm 10.9.4 | 0 vulnerabilities | |
| `eslint` (typescript-eslint strict, react-hooks, bans on `dangerouslySetInnerHTML`/`innerHTML`/`eval`) | 10.12.0 | clean | |
| `tsc --noEmit` | 6.0.3 | clean | |
| `systemd-analyze security --offline=true` | systemd 255 | helper **5.1** MEDIUM, web **1.1** OK | target ≤ 6.0 (SPEC §3.9) met; on the VM: **VM** |
| TLS check (`openssl s_client`) | OpenSSL 3.0.13 | TLS 1.2 refused (`protocol version` alert), TLS 1.3 `TLS_AES_128_GCM_SHA256` | `testssl.sh`/`sslyze` not installed; against the real certificate on the VM: **VM** |
| `axe-core` (all 20 module pages, admin) | 4.10.3 | 0 critical/serious violations | part of `scripts/e2e/full.mjs` when axe-core is resolvable |
| E2E incl. role checks | Playwright, Chromium virtual authenticator | 11/11 | `make test-e2e`; base load 50 sessions: 0 errors, p95 203 ms, web RSS 26 MiB idle / 32 MiB peak |
| SBOM | cyclonedx-gomod 1.9.0, cyclonedx-npm 4.0.0 | 3 Go binaries, web bundle | licences: Go modules MIT, BSD-2/3-Clause, Apache-2.0; npm MIT, OFL-1.1 (fonts), Apache-2.0, 0BSD — no copyleft |
| `lynis` (KANN) | – | **VM** | |
| OWASP ZAP baseline (KANN) | – | not run | not installed; the E2E covers the endpoint set and headers (`TestSecurityHeaders`). Backlog. |

## 2. Catalogue

Status: ✓ checked without open finding, ✓* checked, finding fixed, **VM** re-test on the VM pending.

| ID | Area | Result | Evidence | Status |
|---|---|---|---|---|
| SA-01 | Authentication | WebAuthn with UV required, resident keys, attestation none, exact RP ID and origins, enforced 120 s timeouts; ceremonies single-use, bound to kind and account, capped at 1000 (F-08); clone warning (sign counter) refuses the login. Bootstrap/recovery/invite tokens: 256 bit, stored only as SHA-256, prefix per purpose, constant-time compare, atomic consume in a transaction, TTL 60/30/60 min. Login answers are uniform (`unauthorized`), no user name step (discoverable credentials), no enumeration. | `internal/auth/passkey.go`, `internal/auth/token.go`, `internal/helper/accounts.go`; `TestLoginRejectsWrongOriginAndNoUV`, `TestCeremonyExpiry`, `TestCeremonyLimit`, `TestTokenOneTimeUse`, `TestTokenExpiryAndPurpose`, `TestBootstrapFlow`, `TestPasskeyManagementAndRecovery`; E2E steps 3, 4, 8 | ✓ |
| SA-02 | Authorization | Deny-by-default policy; every op either has a known action (`policy.MustKnow` panics at registration otherwise), is pre-auth or admin-socket only. Pre-auth ops are the login ceremony, `setup.*` (bootstrap token + setup mode) and `setup.state`/`config.web` (no secrets). The helper decides from its own grant table; role and step-up never come from the web process. Step-up bound to the grant, 5 min. Own-scope checks for operators (processes, files as own Linux user). | `internal/helper/server.go` (`Register`, `authorize`), `internal/policy`; `TestDenyByDefault`, `TestGrantAndStepUpEnforcement`, `TestSearchAndPolicy`, `TestCaptureAdminOnlyWithStepUp`, `TestTerminalElevatedNeedsFreshStepUp`; E2E role matrix for operator and read-only | ✓ |
| SA-03 | Sessions | Cookie `__Host-` prefix, `Secure; HttpOnly; SameSite=Strict; Path=/`; grant never in the browser beyond the cookie; new token on login and step-up (no fixation); idle 30 min / absolute 12 h (configurable within 5–60 min / 1–24 h); logout and "end session" revoke in the helper; recovery ends all sessions. Concurrency: no cap per account (F-07). | `internal/web/auth.go`, `internal/helper/grants.go`; `TestSessionEndpointsRequireCookieAndCSRF`, `TestGrantIdleExpiry`, `TestTerminalEndsWithSessionAndIdle`, `TestSessionsPersistListAndRevoke`; E2E step 8 | ✓ (F-07 backlog) |
| SA-04 | Web layer | CSRF: SameSite=Strict + mandatory `X-Daemonica-CSRF` + exact `Origin` on every state-changing request; WebSockets check origin and a one-time ticket. CSP `default-src 'none'; script-src 'self'; style-src 'self' (+nonce)`, `require-trusted-types-for 'script'`, `frame-ancestors 'none'`; HSTS, nosniff, `no-referrer`, COOP/COEP/CORP, `X-Frame-Options: DENY`, Permissions-Policy. CORS never enabled (preflight → 405). XSS: React text rendering only, lint bans raw HTML; terminal output only through xterm.js; log lines, file names, process names and audit fields have control characters stripped server-side. | `internal/web/middleware.go`; `TestCSRF`, `TestSecurityHeaders`, `TestStaticRejectsWritesEvenWithCSRF`, `TestTerminalSocketRejectsForeignOriginAndSession`, `TestSanitizeStripsControlChars`; E2E module pages without CSP or script errors | ✓ |
| SA-05 | Injection | Typed RPC ops with strict JSON decoding; validators for names, paths, units, cron/calendar, CIDRs, packages; external programs only with argv (no shell), fixed binary paths. The only shells are by design: job commands (admin-defined, run as the job's Linux user in a transient unit, DEC-029) and the terminal. Unit properties are passed over D-Bus, not written as unit files from user text. SQL only with placeholders. No response headers built from user input except `Content-Disposition` (ASCII fallback with quotes, separators and control characters replaced, plus `filename*`). | `internal/execx`, `internal/validate`, `internal/jobs/unit.go`; `TestUnitInjection`, `TestUnitProperties`, `TestParseNumFilter`; gosec G204/G304 review (F-04) | ✓ |
| SA-06 | Privilege separation | `helper.sock` 0660 root:daemonica-web, `admin.sock` 0600 root; `SO_PEERCRED` UID check on every connection; ops allowlist (no generic exec); file operations in a worker that assumes the mapped user's credentials; UID 0 mapping refused; web unit unprivileged (score 1.1). | `internal/helper/server.go`, `internal/worker`, `internal/files`; `TestPeerCredOverRealSocket`, `TestGrantRefusesRoot`, `TestSetupRefusesRootAndUnknownUsers` | ✓ |
| SA-07 | TLS and network | TLS 1.3 only, X25519/P-256; certificate sources per DEC-034 (key 0600 owned by the web user, hot reload). Allowlist enforced at accept before the TLS handshake (`RemoteAddr`, no `X-Forwarded-For`); terminals cut when the allowlist changes. ACME window only during an issuance, removed on failure, cancel and at helper start. Open ports: only the dashboard port (loopback until setup). Rate limits per IPv6 /64 (F-01). | `internal/tlsconf`, `internal/web/server.go`, `internal/firewall/window.go`; `TestTerminalCutWhenAllowlistChanges`, `TestOpenWindow`, `TestCloseStaleWindows`, `TestCertCancelAndWindow`, `TestRateLimiterIPv6Prefix`; `openssl s_client`; `ss -ltnp`; integration `TestACMEWindow` | ✓* / **VM** |
| SA-08 | Secrets | Tokens and grants only as hashes; WebAuthn private keys never on the server; TLS key 0600; no secrets in audit params (per-op allowlist `AuditKV`), in logs or in process lists (tokens passed over sockets, never argv); config and state 0600/0700 root; `test_vm.md` never tracked. | `internal/helper/server.go` (`audit`), `scripts/check-secrets.sh`, gitleaks; `TestHashIsNotToken`, `TestTokensPersistAcrossReopen` | ✓* (F-06) |
| SA-09 | Files and terminal | `openat2` with `RESOLVE_NO_MAGICLINKS`, writes with `RESOLVE_NO_SYMLINKS` and `*at()` calls without following symlinks (TOCTOU); hard-blocked Daemonica data, confirmation for sensitive paths; upload/download size limits and streaming deadlines; downloads with `nosniff` and attachment disposition. Terminal: transient unit per session with `TasksMax`/`MemoryMax`, limit per account, ends with the session or idle timeout; elevated terminal needs a fresh step-up. | `internal/files/ops_linux.go`, `internal/pty`; `TestSymlinkRaceRootMode`, `TestWriteSymlinkedDirRefused`, `TestTerminalLimitPerAccount`, `TestTerminalEndsWithSessionAndIdle` | ✓ |
| SA-10 | Audit | All privileged ops and all denials audited by the helper; SHA-256 chain with verification (UI and `daemonica-admin audit-verify`); records sanitized against log forging; params per-op allowlist, never contents. Append-only flag and rotation were missing (F-02). | `internal/audit`; `TestChainAppendVerifyAndResume`, `TestVerifyDetectsTampering`, `TestRotationContinuesChain`, `TestAppendOnlyRotation`; integration `TestInstalledAuditLog` | ✓* / **VM** |
| SA-11 | Availability | Pre-auth rate limit 0.5/s burst 10 per client (IPv6 /64), global 10/s burst 100, exponential backoff after failures, no account lockout; header 32 KiB, bodies limited per endpoint, server timeouts (header 10 s, read 60 s, write 120 s, streams with their own deadlines); ceremony and terminal caps; plan/apply/confirm with helper-side rollback timer and crash journal. Base load: 50 sessions without errors. | `internal/web/ratelimit.go`, `cmd/daemonica-web/main.go`; `TestRateLimiterBurstAndBackoff`, `TestGlobalLimit`, `TestTokenFailuresTriggerBackoff`, `TestRejectsOversizedHeaderWithoutAllocating`, `TestAutoRollbackWithoutConfirm`, `TestAllowlistPlanApplyConfirmRollback`; `scripts/e2e/load.mjs` | ✓* (F-01, F-08 backlog) |
| SA-12 | Hardening and packaging | Units: helper 5.1, web 1.1 (offline); exceptions with reasons in `docs/ARCHITECTURE.md`. Maintainer scripts: directories 0700/0750 with fixed owners, purge removes job units, ACME window and the append-only flag; downgrade guard refuses a newer database schema; update/rollback path documented in INSTALL.md §5. `shellcheck` clean. | `packaging/`; `store_test.go` (newer schema refused); E2E; **VM**: `systemd-analyze security`, upgrade a07a055 → RC, purge | ✓ / **VM** |
| SA-13 | Supply chain | Go modules pinned in `go.sum`, npm in `package-lock.json`; Go toolchain from go.dev with verified checksum (B4); SBOM per binary and for the web bundle; licences permissive only; no package sources, archives or images fetched at runtime in Phase 1 except the user-configured GitHub script collections (pinned to a commit, DEC-030) and ACME (D-19). Release signing: the RC is `-UNSIGNED-TESTONLY` (no signing key yet). Reproducible builds: not verified (backlog). | `make sbom`, `make sec`, `go.sum` | ✓ |
| SA-14 | Privacy | No telemetry, no update checks, no external fonts or CDNs (CSP `default-src 'none'`, fonts bundled); outbound connections only: ACME CA (when issuing), GitHub API for script collections the admin added, apt (package module, system configuration). | code search for HTTP clients (`internal/scripts/github.go` only), CSP | ✓ |
| SA-15 | Network analysis | Capture admin-only with step-up at every start; limits duration ≤ 30 min, packets, file size ≤ 1 GiB, snaplen 96 default, total quota, stops below 10 % free space; `tcpdump` in a transient unit, own memory-safe Go parser for the live view; dashboard port excluded by default; filter from the guided builder, the free BPF expression (advanced) limited to a character allowlist and passed to tcpdump as one argv element; retention 24 h and deletion; download as attachment. Firewall logs: control characters stripped, volume limits, no reverse DNS or external lookups. | `internal/capture`, `internal/firewall`; `TestCaptureAdminOnlyWithStepUp`, `TestManagerLimits`, capture parser fuzz tests | ✓ |

## 3. Findings

| ID | Title | Severity | Component | Status | Re-test |
|---|---|---|---|---|---|
| F-01 | Rate limit and backoff per IPv6 address | Medium | `internal/web/ratelimit.go` | fixed | `TestRateLimiterIPv6Prefix` ✓ |
| F-02 | Audit log not append-only, no rotation | Medium | `internal/audit`, helper | fixed (DEC-035) | unit tests ✓; `TestInstalledAuditLog` **VM** |
| F-03 | `golang.org/x/net` 0.59.0 with known (unreached) vulnerabilities | Low | `go.mod` | fixed (0.62.0) | `govulncheck` ✓ |
| F-04 | gosec findings unreviewed; `make sec` ran gosec without the project's annotations | Low | `Makefile`, `.golangci.yml` | fixed | `golangci-lint run` 0 issues ✓ |
| F-05 | Static analysis: unused code, deprecated APIs | Info | several | fixed | `staticcheck` clean ✓ |
| F-06 | Secret scans: two false positives, `check-secrets.sh` failed on a test fixture | Info | `.gitleaksignore`, `scripts/check-secrets.sh` | fixed | gitleaks and script clean ✓ |
| F-07 | No cap on concurrent sessions per account | Low | `internal/helper/grants.go` | backlog | – |
| F-08 | Pending-ceremony table and global rate limit can be exhausted from within the allowlist | Low | `internal/auth/passkey.go`, `internal/web/ratelimit.go` | backlog | – |
| F-09 | Helper unit exposure 5.1 | Info | `daemonica-helper.service` | accepted by design (target ≤ 6.0 met) | **VM** score |
| F-10 | `osv-scanner` and `vuln.go.dev` not reachable from the build environment | Info | tooling | open → VM | **VM** |
| F-11 | No reproducible-build check, unsigned RC | Info | release | backlog | – |
| F-12 | Expired or untrusted certificate locks the admin out of certificate changes | Medium | certificates (DEC-034), `daemonica-admin` | fixed | `TestCertAdminChannel` ✓; `tls-status`/`tls-install`/`tls-issue` against the local stack ✓; **VM** |
| F-13 | Firewall log entries lost to kernel rate limiting were not shown (SPEC §7.6b "soweit erkennbar") | Low | `firewall.logs` | fixed | `TestFirewallLogsAndBlockSource` ✓ |

### F-01 — Rate limit and backoff per IPv6 address (Medium, fixed)
- **Description:** Buckets and the failure backoff were keyed by the full client address. A host usually owns a whole IPv6 /64 and can use any address in it, so it could bypass the per-IP login limit and the backoff by rotating addresses; only the global limit remained. IPv4-mapped IPv6 addresses also got their own bucket.
- **Evidence:** code review of `RateLimiter.Allow/Fail/Success`.
- **Fix:** key IPv6 clients by their /64 prefix and unmap IPv4-mapped addresses (`clientKey`).
- **Re-test:** `TestRateLimiterIPv6Prefix` (same /64 shares the bucket, other /64 independent, mapped address shares the IPv4 backoff).

### F-02 — Audit log not append-only, no rotation (Medium, fixed)
- **Description:** SPEC §3.8 asks for `chattr +a` (SOLL) and a rotation that continues the chain. Neither existed: the log could be rewritten by any root process without anything stopping it (only detected by the next verification), and it grew without bound (`/var/log` exhaustion over time).
- **Fix:** DEC-035: the helper sets the append-only flag, rotates at 32 MiB keeping four files with the chain continued across files, verification and queries cover all files; purge removes the flag.
- **Re-test:** `TestRotationContinuesChain`, `TestVerifyAllSingleFileNeedsGenesis`, `TestAppendOnlyRotation` (ran with the real flag on ext4); on the VM `TestInstalledAuditLog` (**VM**).

### F-03 — `golang.org/x/net` with known vulnerabilities (Low, fixed)
- **Description:** `govulncheck` listed 7 vulnerabilities in `x/net` 0.59.0 (HTML parser, HTTP/2). None is reachable from Daemonica's code (the HTTP/2 server is the standard library's).
- **Fix:** upgrade to 0.62.0 (with `x/sys`, `x/text`, `x/sync`, `x/tools` minor updates). **Re-test:** `govulncheck`: 0 reachable, 0 in imported packages.

### F-04 — gosec findings unreviewed (Low, fixed)
- **Description:** `make sec` ran standalone `gosec`, which ignores the project's `//nolint:gosec` annotations, so it always failed and its 101 raw findings (mostly tests) were not tracked.
- **Fix:** gosec runs through golangci-lint (`make lint` and `make sec`); the 23 findings in production code were reviewed: integer conversions with checked bounds (G115), paths from allowlists or helper-generated names (G304, G703), intended modes for world-readable script trees, fstab and the run directory (G301/G302), binary paths mistaken for credentials (G101), the terminal watcher that must outlive the request (G118). Each line carries the reason.

### F-07 — No cap on concurrent sessions per account (Low, backlog)
- **Description:** an account can hold any number of sessions. Creating them needs a passkey assertion and is bounded by the login rate limit (0.5/s per client, 10/s global) and the idle timeout (30 min), so memory and database growth stay bounded (order of 10⁴ grants worst case).
- **Recommendation:** cap per account (e.g. 50) with "oldest session ends" in Phase 2.

### F-08 — Ceremony table and global limit exhaustible from within the allowlist (Low, backlog)
- **Description:** pending ceremonies are capped at 1000 for 120 s. A client inside the allowlist with ≥ 12 /64 prefixes (or IPv4 addresses) could keep the table full; the global limit (10/s) itself lets the same client slow everyone's login. This follows the SPEC design (no account lockout, per-IP plus global limit) and needs allowlist access.
- **Recommendation:** in Phase 2 reserve part of the global budget for clients with a valid session cookie and evict the oldest login ceremony instead of refusing new ones.

### F-12 — Expired or untrusted certificate locks the admin out of certificate changes (Medium, fixed)
- **Description:** browsers refuse WebAuthn on origins with certificate errors. Once the dashboard certificate expired (e.g. a missed manual DNS-01 renewal) or an untrusted one was installed (Let's Encrypt staging chosen in the settings), passkey login and step-up stopped working, and replacing the certificate needs step-up. The only way back was editing `/var/lib/daemonica/tls` by hand; `daemonica-admin tls-status` was still a stub.
- **Fix:** admin-socket operations `admin.cert_status/issue/dns_confirm/cancel/upload` and the console commands `tls-status`, `tls-issue` (HTTP-01, TLS-ALPN-01, DNS-01 interactive, Ctrl-C cancels and closes the ACME window) and `tls-install`; the UI warns when staging is chosen; INSTALL.md §3 explains the way back.
- **Re-test:** `TestCertAdminChannel` (reachable only on the admin socket, upload works, terms required); console commands against the local stack (status, install, failing staging issuance reported).

### F-13 — Firewall log entries lost to rate limiting not shown (Low, fixed)
- **Description:** SPEC §7.6b asks to show entries lost to rate limiting as far as detectable; the firewall log view did not.
- **Fix:** `firewall.logs` also counts kernel `N callbacks suppressed` lines in the same period and the page shows a warning. ufw's own `LOG` rate limit drops silently and stays undetectable (said in the result field's comment and in STATUS).

### F-09, F-10, F-11
- **F-09:** remaining helper exposure comes from capabilities and file system access the admin modules need (users, files, firewall, packages, disks); listed with reasons in `docs/ARCHITECTURE.md` "Hardening exceptions".
- **F-10:** the build environment's network policy refuses `api.osv.dev` and `vuln.go.dev`. `govulncheck` ran against a local copy of the Go vulnerability database from GitHub; `osv-scanner` runs on the VM in the full test.
- **F-11:** the RC is built without a signing key (`-UNSIGNED-TESTONLY`, SPEC §6.6); reproducible builds are not verified yet.

## 4. Re-test on the VM (filled in during the full test)

| Check | Result |
|---|---|
| `systemd-analyze security daemonica-helper daemonica-web` | **VM** |
| `TestInstalledAuditLog` (append-only, chain) | **VM** |
| `osv-scanner scan source -r .` | **VM** |
| TLS check against the dashboard with its real certificate | **VM** |
| `TestACMEWindow` against the real ufw (`DAEMONICA_FIREWALL_TESTS=1`) | **VM** |
| `make test-e2e` on the fresh installation (`E2E_STRICT=1`) incl. base load and idle RAM | **VM** |
| `lynis audit system` (KANN) | **VM** |
