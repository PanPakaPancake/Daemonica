# Threat model (STRIDE-oriented)

Scope: Phase 1, state at the end of M1.8 (phase audit: `docs/security/AUDIT-PHASE-1.md`). Attackers A1–A6 as in SPEC §3.1.

| Threat | Attacker | Asset | Mitigation (implemented ✓ / planned ○) |
|---|---|---|---|
| **S**poofing a user | A1, A2 | Accounts | Passkey-only login with UV ✓; no passwords ✓; uniform login errors ✓; helper verifies WebAuthn ✓ |
| Spoofing the web process toward the helper | A6 | Helper ops | `SO_PEERCRED` UID check ✓; socket 0660 root:daemonica-web ✓ |
| Spoofing root toward the admin socket | A6 | Admin ops | admin.sock 0600 ✓ + UID 0 check ✓ |
| **T**ampering with configuration | A3 | Allowlist, TLS, setup state | Config owned by helper, root 0600 ✓; web gets read-only copy ✓ |
| Tampering with audit records | A3, A6 | Audit log | Written only by helper ✓; hash chain + verify across rotated files ✓; `chattr +a` ✓ (DEC-035) |
| Tampering via injection | A5, A3 | System | Typed ops ✓; strict validators ✓; argv-only exec for all ops ✓ |
| **R**epudiation | A5 | Accountability | All privileged ops incl. denials audited ✓ |
| **I**nformation disclosure before login | A1 | Everything | Only shell, assets, setup/login endpoints ✓; no pprof/debug/version banner ✓ |
| Disclosure via XSS | A1, A5 | Session | Strict CSP without `unsafe-*` ✓; Trusted Types ✓; React text rendering, no `dangerouslySetInnerHTML` ✓ |
| Disclosure via network exposure | A1 | Dashboard | Allowlist at accept before TLS ✓; loopback default ✓; TLS 1.3 only ✓ |
| **D**enial of service | A1 | Availability | Rate limits per IP (IPv6 per /64) + global, backoff ✓; header/body/time limits ✓; no account lockout ✓ |
| Lock-out by misconfiguration | Admin error | Access | Plan → Apply → Confirm with helper-side rollback + crash journal ✓; `allowlist-reset` ✓ |
| **E**levation from web compromise | A3 | Root | No generic exec ✓; helper re-authorizes every op from its own grant table ✓; role never taken from web ✓; UID 0 mapping refused ✓ |
| Elevation by low-privilege account | A5 | Root | Deny-by-default policy ✓; step-up in helper with a fresh passkey ceremony ✓ |
| Supply chain | A4 | Build | Modules pinned in go.sum, npm lockfile ✓; SBOM (CycloneDX) ✓; govulncheck, npm audit, gitleaks, gosec in `make sec` ✓ |

## Open risks

See the findings and the "decision needed" list in `docs/security/AUDIT-PHASE-1.md`.
