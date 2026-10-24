# Decisions (ADR log)

Format per SPEC §0.3: ID, date, context, decision, rejected alternatives, security assessment.

---

## DEC-001 — Repository name vs. product name
- **Date:** 2026-10-24
- **Context:** The owner created the repository `PanPakaPancake/Daemonica`; the SPEC names the product **Daemonica** (A-01).
- **Decision:** Product, binaries, package and UI use **Daemonica** as specified. The Go module path follows the repository: `github.com/PanPakaPancake/daemonica`.
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
- **Decision:** `/var/lib/daemonica-helper/config.json` (root 0600), written atomically (temp + fsync + rename + dir fsync), validated on load and on every update. The web process receives a read-only subset via the `config.web` RPC.
- **Rejected:** Storing settings in `web.db` (web process could alter its own allowlist after compromise, A3).
- **Security:** Improves A3 resistance: a compromised web process cannot widen the allowlist.

## DEC-005 — RPC framing and grants
- **Date:** 2026-10-24
- **Decision:** 4-byte big-endian length + strict JSON (unknown fields rejected), protocol version 1, max 1 MiB. Operation names restricted by regex. The web process passes an opaque **grant token**; the helper stores only its SHA-256 hash and resolves account, role, Linux user and step-up itself. One connection per call (simplicity, failure isolation).
- **Rejected:** gRPC/protobuf (extra dependency, larger attack surface); HMAC-signed self-contained grants (revocation harder).
- **Security:** Web cannot assert roles (SPEC §3.2 rule 4). Grants issued only for UID ≠ 0.

## DEC-006 — Audit log mirror
- **Date:** 2026-10-24
- **Decision:** Each audit record is fsynced to `/var/log/daemonica/audit.log` and mirrored as a JSON line to stdout of the helper (journald, `SyslogIdentifier=daemonica-helper`). A dedicated `daemonica-audit` identifier requires native journald protocol support and is planned with the journal module (M1.1).
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

## DEC-012 — Branding asset and product name shown in the UI
- **Date:** 2026-10-24
- **Context:** The owner supplied the logo (`assets/branding/daemonica-logo-source.png`, 1672×940, opaque black background). The wordmark reads **"Daemonica"**, while SPEC A-01 (v1.2) carried the misspelling "Daemonia". The repository is named Daemonica.
- **Decision:** (1) Background made transparent by an edge-connected flood fill of near-black pixels (max channel ≤ 10) with 0.8 px feathering, then tightly cropped → `assets/branding/daemonica-logo.png`; derived PNGs in `web/public/brand/` (240/480/960 px wide) and square mascot crops for favicon and collapsed sidebar (32/48/180/512). No redrawing, recolouring or new poses (SPEC §5.4). (2) The user-visible product name follows the logo: **Daemonica** (page title, alt texts, i18n `app.name`). (3) Superseded by DEC-013: the owner confirmed "Daemonica" and all technical identifiers were renamed.
- **Rejected:** Showing the opaque image on the dark UI (visible black box); renaming every technical identifier before confirmation.
- **Security:** none (static same-origin images, CSP `img-src 'self'`).

## DEC-013 — Rename to "Daemonica", dark default theme, self-drawn icons
- **Date:** 2026-10-24
- **Context:** Owner: the correct name is "Daemonica" everywhere (incl. SPEC); supplied an app icon; dark design should be the default; UI may use symbols for functions/menu items.
- **Decision:** (1) All identifiers renamed (`daemonica-web/-helper/-admin`, units, Go module `github.com/PanPakaPancake/daemonica`, paths `/var/lib/daemonica*`, `/run/daemonica`, `/var/log/daemonica`, cookie `__Host-daemonica_session`, header `X-Daemonica-CSRF`, token prefix unchanged `dmn_`). SPEC bumped to v1.3 (A-01 confirmed). Existing VM install migrated by moving the state directories; all sessions end because the cookie name changed. (2) The supplied icon is stored unchanged as `assets/branding/daemonica-mascot.png`; favicon/apple-touch/sidebar icons are pure downscales (SPEC §5.4). (3) Theme default is **dark** regardless of `prefers-color-scheme`; only an explicit toggle is stored (localStorage, per browser). (4) Icons are a small set of self-drawn 24×24 stroke SVGs in `web/src/components/icons.tsx`, always `aria-hidden` next to visible or screen-reader text.
- **Rejected:** `lucide-react` (fine licence, but a new dependency + age rule for ~25 glyphs); following `prefers-color-scheme` (owner preference).
- **Security:** none; inline SVG is React-rendered JSX, no `innerHTML`, CSP unchanged.

## DEC-014 — Account administration and invitations
- **Date:** 2026-10-24
- **Context:** SPEC §7.1 requires inviting accounts with a one-time token (60 min), role changes, disable/delete and last-admin protection.
- **Decision:** `accounts.invite` creates the account without a passkey and returns a one-time `invite` token (256 bit, hashed, 60 min; reissuing revokes the previous one). The UI hands out `https://<host>/invite#token=…`: the fragment is never sent in requests or logged; the page reads it once and strips it from the URL. Redemption (`invite.begin/finish_register`) shares one implementation with console recovery. "Usable admin" = enabled admin with ≥ 1 passkey; demoting, disabling or deleting the last one is refused inside one SQLite transaction. Admins cannot change, disable or delete their **own** account in the UI (self-lockout guard; console recovery stays available). Every role/state change ends all sessions of the target account, so grants never carry a stale role. Listing accounts is admin-only without step-up (`accounts.read`); every change needs step-up (`accounts.manage`, Annex A).
- **Rejected:** Showing the invite token as plain text only (error-prone copy); keeping sessions alive across role changes (stale privileges).
- **Security:** No account enumeration pre-auth (invalid/expired tokens → uniform `token_invalid`); invite tokens are bound to one account ID.

## DEC-015 — Allowlist changes via Plan → Apply → Confirm
- **Date:** 2026-10-24
- **Context:** SPEC §3.2 rule 10 / §3.6: allowlist changes need a preview, a confirmation timer independent of browser and web process, and must include the current IP or warn.
- **Decision:** Helper planner kind `allowlist` (payload old/new list, journaled for crash recovery). Loopback is always kept. Excluding the caller's IP is refused with `lockout_protection` unless `confirm_lockout` is set (UI: explicit checkbox); public lists need `confirm_public`. The apply response sets `Connection: close` (HTTP/2: GOAWAY) and triggers an immediate config reload in the web process; the confirmation must arrive on a TCP connection accepted **after** the apply (web passes the accept time, helper compares with `applied_at`). Without confirmation the helper reverts after 90 s. In addition, the web process now re-checks the allowlist on every request, so keep-alive connections from removed networks lose access at once.
- **Rejected:** Confirm over the existing connection (proves nothing); client-side timers (die with the browser).
- **Security:** A compromised web process could fake the accept time, but it could also confirm anyway (A3 can act within the logged-in admin's rights); the mechanism protects against honest mistakes, the helper still enforces step-up and owner binding.

## DEC-016 — M1.1 data sources: /proc collector, D-Bus, journalctl JSON
- **Date:** 2026-10-24
- **Context:** SPEC §7.2 and §4.1 (prefer /proc, /sys, D-Bus, statfs over command output).
- **Decision:** (1) One `sysinfo.Collector` in the helper samples /proc, /sys and statfs every 3 s; all sessions read the cached snapshot (no polling storm). (2) systemd is controlled exclusively over D-Bus with `github.com/godbus/dbus/v5` **v5.2.2** — v5.2.3/v5.2.4 are younger than 14 days (SPEC §4.4), BSD-2-Clause, no transitive dependencies. (3) journald has no stable, CGO-free Go reader; the helper runs `/usr/bin/journalctl --output=json` with an argv array, fixed environment, 20 s timeout and 32 MiB output cap (`internal/execx`); every value is a single `--opt=value` element, leading dashes are rejected, search text is regex-escaped. Results are capped at 640 KiB to stay below the 1 MiB RPC frame. (4) Process signals use a pidfd (`os.FindProcess`) after re-reading the process and comparing its start time with the one shown to the user (PID-reuse guard). (5) Pending update counts come from Ubuntu's update-notifier summary until the apt module (M1.7) exists.
- **Rejected:** `systemctl`/`ps`/`df` output parsing; cgo `sd-journal` bindings (CGO_ENABLED=0).
- **Security:** argv-only execution, no shell; all system strings sanitised (control/bidi characters removed) before leaving the helper.

## DEC-017 — Log follow by polling until the WebSocket layer lands (M1.4)
- **Date:** 2026-10-24
- **Context:** SPEC §7.2 asks for live log follow "per WebSocket". The WebSocket infrastructure (tickets, origin check, rate limits) is built with the terminal in M1.4.
- **Decision:** For now the UI polls `journal.query` with the last cursor every 1.5 s while "Follow" is active (meets the < 2 s requirement). The endpoint is switched to `/api/v1/ws/journal` in M1.4 without API changes for the helper.
- **Security:** Same session, CSRF and rate-limit rules as every other API call; no new attack surface.

## DEC-018 — Per-response style nonce for UI-library <style> elements
- **Date:** 2026-10-24
- **Context:** The headless screenshot test (scripts/e2e/screens.mjs) showed CSP violations: Radix dialogs (via react-remove-scroll) insert a `<style>` element for the body scroll lock, which `style-src 'self'` blocks. Alternatives were dropping modal behaviour (focus trap, a11y regression) or `'unsafe-inline'` (not acceptable).
- **Decision:** `index.html` is rendered per response with a fresh 128-bit nonce; the CSP of that response becomes `style-src 'self' 'nonce-…'`. The app passes the nonce to `get-nonce` (the hook the Radix stack reads). Scripts stay `script-src 'self'` without nonce; API and asset responses keep the static CSP. Dependency `get-nonce` 1.0.1 (MIT, no dependencies) was already a transitive dependency and is now direct.
- **Security:** Only `<style>` elements carrying the nonce are allowed; style injection by an attacker would additionally need the per-response nonce. No script relaxation. Covered by `TestIndexGetsFreshStyleNonce` and the screenshot smoke test (fails on any console/CSP error).
