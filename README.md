# Daemonica

Web-based administration dashboard for a single Debian/Ubuntu server — passkey-only
login, privilege-separated helper, tamper-evident audit log.

> **Status:** Phase 1, milestone M1.0 in progress. See [`docs/STATUS.md`](docs/STATUS.md)
> for what works today and the open blockers. The specification lives in `SPEC.md` (German).

## Components

| Binary | Runs as | Purpose |
|---|---|---|
| `daemonica-web` | `daemonica-web` | HTTPS (TLS 1.3), UI, API; no privileges |
| `daemonica-helper` | root | Typed, allowlisted privileged operations over Unix sockets |
| `daemonica-admin` | root (CLI) | Bootstrap, recovery, emergency commands |

Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · Threat model:
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) · Decisions: [`docs/DECISIONS.md`](docs/DECISIONS.md) ·
Installation (de): [`docs/INSTALL.md`](docs/INSTALL.md)

## Development

```bash
make lint test      # gofmt, go vet, golangci-lint (if installed), tests with -race
make build          # static binaries for amd64 and arm64 in dist/
make package        # .deb (-UNSIGNED-TESTONLY without the owner's signing key)
make sec            # govulncheck/gosec/gitleaks when installed + secret scan
```

`test_vm.md` holds local connection details for the test VM and is git-ignored.

## License

Not yet decided — see [`LICENSE`](LICENSE).
