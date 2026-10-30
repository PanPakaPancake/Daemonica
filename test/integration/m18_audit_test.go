//go:build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

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

// TestHelperRestartsWithAppendOnlyLog restarts the installed helper: with the
// audit log append-only, nothing in the unit may chown or chmod it at start
// (rc2 failed with LogsDirectory=, status 240/LOGS_DIRECTORY).
func TestHelperRestartsWithAppendOnlyLog(t *testing.T) {
	if _, err := os.Stat("/var/log/daemonica/audit.log"); err != nil {
		t.Skip("daemonica not installed")
	}
	if out, err := exec.Command("systemctl", "restart", "daemonica-helper").CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	for range 30 {
		out, _ := exec.Command("systemctl", "is-active", "daemonica-helper").Output()
		if strings.TrimSpace(string(out)) == "active" {
			if _, err := os.Stat("/run/daemonica/admin.sock"); err == nil {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	out, _ := exec.Command("systemctl", "status", "daemonica-helper", "--no-pager").CombinedOutput()
	t.Fatalf("helper not active after restart:\n%s", out)
}
