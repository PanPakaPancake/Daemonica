#!/bin/sh
# Minimal secret scan used by `make sec` when gitleaks is unavailable.
# Fails on private keys, tokens in the Daemonica format, or test_vm.md being tracked.
# (sshkeys_test.go only holds the header line of a key, to test refusing it.)
set -eu
fail=0
if git ls-files --error-unmatch test_vm.md >/dev/null 2>&1; then
  echo "ERROR: test_vm.md is tracked by git (must stay local)"; fail=1
fi
if git grep -nI -E -e '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' -e 'dmn_(bootstrap|recovery|invite|grant)_[A-Za-z0-9_-]{40,}' -- . ':!scripts/check-secrets.sh' ':!internal/sshkeys/sshkeys_test.go' 2>/dev/null; then
  echo "ERROR: possible secret committed"; fail=1
fi
[ "$fail" -eq 0 ] && echo "secret scan: ok"
exit "$fail"
