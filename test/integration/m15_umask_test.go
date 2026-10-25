//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

// TestLauncherUmaskNetplan reproduces the M1.5 acceptance failure: under the
// helper's UMask=0077 `netplan generate` wrote networkd files that
// systemd-networkd could not read. Through the launcher the children run
// with umask 022 and the generated file is readable by its group.
func TestLauncherUmaskNetplan(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/usr/sbin/netplan"); err != nil {
		t.Skip("netplan not installed")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	execx.Launcher = self
	defer func() { execx.Launcher = "" }()
	ctx := context.Background()

	res, err := execx.Run(ctx, 10*time.Second, 4096, nil, "/bin/sh", "-c", "umask")
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "0022" {
		t.Fatalf("launcher umask: %q %v", res.Stdout, err)
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/netplan"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "network:\n  version: 2\n  ethernets:\n    ittest0:\n      addresses: [192.0.2.10/24]\n      routes:\n        - to: default\n          via: 192.0.2.1\n"
	if err := os.WriteFile(filepath.Join(root, "etc/netplan/50-it.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := execx.Run(ctx, 30*time.Second, 1<<16, nil, "/usr/sbin/netplan", "generate", "--root-dir", root); err != nil || res.ExitCode != 0 {
		t.Fatalf("netplan generate: %v %s", err, res.Stderr)
	}
	f := filepath.Join(root, "run/systemd/network/10-netplan-ittest0.network")
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %v", f, fi.Mode())
	if fi.Mode().Perm()&0o040 == 0 {
		t.Fatalf("generated file not group-readable: %v", fi.Mode())
	}
	if g, err := user.LookupGroup("systemd-network"); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Gid != 0 {
			if g.Gid != strconv.FormatUint(uint64(st.Gid), 10) {
				t.Errorf("group %d, want systemd-network (%s)", st.Gid, g.Gid)
			}
		}
	}

	// Without the launcher the same run reproduces the failure, so the test
	// really covers the umask (and not netplan's own chmod).
	execx.Launcher = ""
	root2 := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root2, "etc/netplan"), 0o755)
	_ = os.WriteFile(filepath.Join(root2, "etc/netplan/50-it.yaml"), []byte(yaml), 0o600)
	if out, err := exec.Command("/usr/sbin/netplan", "generate", "--root-dir", root2).CombinedOutput(); err != nil {
		t.Logf("netplan generate without launcher: %v %s", err, out)
	} else if fi, err := os.Stat(filepath.Join(root2, "run/systemd/network/10-netplan-ittest0.network")); err == nil {
		t.Logf("without launcher: %v", fi.Mode())
	}
}
