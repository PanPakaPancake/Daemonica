# Test report — Phase 1

Release candidate `0.1.0~rc1`, branch `wip/m18`. Date: 2026-10-29.
Columns "build environment" were measured in the development container (Ubuntu 24.04,
systemd 255 without running systemd, local helper and web process); "VM" is filled in during the
full test on the freshly installed VM (M1.8 step 6).

## Summary

| Area | Build environment | VM |
|---|---|---|
| Go unit tests (`go test -race ./...`) | **238 passed**, 0 failed, 35 packages | – |
| Go statement coverage | **63.7 %** | – |
| Fuzz targets (RPC frames, validators, file names, sysinfo parsers, SSH keys, capture parser) | 6, seed corpora pass | – |
| Frontend tests (vitest) | **39 passed** in 10 files | – |
| Type check, lint, i18n (`tsc -b`, eslint, `i18n:check`) | clean; 1929 keys de/en | – |
| Integration tests (`-tags integration`, need root and a real host) | – | 24 tests |
| End-to-end (`make test-e2e`) | **11/11** steps | **VM** (with `E2E_STRICT=1`) |
| Base load: 50 parallel sessions | 0 failed requests, p95 **212 ms** | **VM** |
| Web process RSS idle / under load / idle after | **26 / 32 / 32 MiB** (target < 100 MiB) | **VM** |
| Accessibility (axe-core, 20 pages) | 0 critical or serious violations | **VM** |
| Security tools | see `docs/security/AUDIT-PHASE-1.md` §1 | **VM** items there |
| `systemd-analyze security` | helper 5.1, web 1.1 (offline) | **VM** |
| Install → setup → modules → roles → update → purge | – | **VM** and owner checklist |

## End-to-end test

`scripts/e2e/full.mjs` drives Chromium with Playwright against a freshly installed, not yet set
up Daemonica. Passkeys come from Chromium's virtual WebAuthn authenticator (CTAP2, resident keys,
user verification); the dashboard domain is mapped to 127.0.0.1, so nothing leaves the host.
Report: `report.json` plus screenshots per step and page.

| # | Step | Checks |
|---|---|---|
| 1 | Setup on loopback | bootstrap token, domain, allowlist, own certificate (test CA) |
| 2 | Switch to the domain | web service restarts on the domain with the uploaded certificate (verified against the test CA, not the setup certificate) |
| 3 | First passkey on the domain | registration through the wizard with the virtual authenticator, account mapped to a Linux user |
| 4 | Bootstrap token consumed | the same token is refused (`setup_complete`) |
| 5 | All 20 module pages as admin | no script errors, no CSP violations, no "not found"; API 5xx are reported (and fail with `E2E_STRICT=1`); axe-core per page |
| 6 | Step-up with passkey | inviting the operator asks for the passkey; the second invitation within 5 min does not |
| 7–8 | Invitations operator and read-only | accept the link in a fresh browser context with its own authenticator; API role matrix (allowed/denied) and navigation per role |
| 9 | Logout and login | passkey login, session valid |
| 10 | Anonymous access | overview, services, accounts, settings and files answer 401 |
| 11 | Base load and idle memory | see below |

In the build environment the services page and the time zone list answer 500 because systemd
does not run there; on the VM the strict mode treats any 5xx as a failure.

## Base load and memory

`scripts/e2e/load.mjs`, run as the last E2E step: 50 sessions, each logged in with a real passkey
assertion signed with the credential exported from the virtual authenticator, each from its own
loopback address (the login rate limit is per client). Every session polls the overview every 3 s
and its session every 60 s; every third session also the process list (3 s), network, firewall
(10 s) and jobs (15 s), as open dashboard tabs do. Duration 120 s by default (20 s in the build
environment run).

| Measurement | Build environment | VM |
|---|---|---|
| Logins (50, one after the other) | 0.5 s | **VM** |
| Requests | 559 (28/s) | **VM** |
| Failed requests | 0 | **VM** |
| Latency p50 / p95 / p99 / max (all paths) | 2 / 212 / 251 / 277 ms | **VM** |
| Web process RSS before / peak / 60 s after | 26.3 / 32.2 / 32.2 MiB | **VM** |
| Helper RSS before / after | 30.9 / 32.1 MiB | **VM** |

## Commands

```bash
make lint test                     # Go and frontend checks, unit tests
make sec sbom                      # security tools, SBOM
sudo go test -tags integration ./test/integration/   # on the VM
sudo make test-e2e E2E_USERS=pancake,op,leser E2E_STRICT=1   # on a fresh VM before setup
```
