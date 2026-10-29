//go:build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/audit"
)

// TestInstalledAuditLog checks the audit log of the installed package (SPEC
// §3.8): append-only ("chattr +a") and an intact chain across rotated files.
func TestInstalledAuditLog(t *testing.T) {
	const p = "/var/log/daemonica/audit.log"
	if _, err := os.Stat(p); err != nil {
		t.Skip("daemonica not installed")
	}
	out, err := exec.Command("lsattr", p).Output()
	if err != nil {
		t.Fatal(err)
	}
	if attrs, _, _ := strings.Cut(string(out), " "); !strings.Contains(attrs, "a") {
		t.Fatalf("audit log not append-only: %s", out)
	}
	if res := audit.VerifyAll(p, audit.DefaultKeep); !res.OK {
		t.Fatalf("chain: %+v", res)
	}
}
