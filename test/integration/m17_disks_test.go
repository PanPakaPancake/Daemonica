//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/disks"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
)

// TestDisksOnHost (M1.7b, DEC-032): lsblk and the real fstab parse, the
// current fstab passes findmnt --verify through our renderer unchanged, a
// broken fstab is rejected before saving, and mount unit names match
// systemd-escape.
func TestDisksOnHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ctx := context.Background()
	run := disks.Run(netcfg.ExecRunner)
	bs, err := disks.Blocks(ctx, run)
	if err != nil || len(bs) == 0 {
		t.Fatalf("lsblk: %v %+v", err, bs)
	}
	var root bool
	for _, b := range disks.Flatten(bs) {
		t.Logf("%s %s %d %s %s %v", b.Path, b.Type, b.Size, b.FSType, b.UUID, b.Mountpoints)
		for _, m := range b.Mountpoints {
			root = root || m == "/"
		}
	}
	if !root {
		t.Error("no device mounted on /")
	}
	text, err := os.ReadFile(disks.FstabPath)
	if err != nil {
		t.Fatal(err)
	}
	f := disks.ParseFstab(string(text))
	if got := disks.Render(f, f.Entries); got != string(text) {
		t.Fatalf("unchanged render differs:\n%s", got)
	}
	ps, err := disks.Verify(ctx, run, string(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		t.Logf("current fstab: %+v", p)
	}
	if disks.Blocking(ps) {
		t.Errorf("current fstab does not verify: %+v", ps)
	}
	broken := append(f.Entries, disks.Entry{Spec: "UUID=00000000-dead-beef-0000-000000000000", File: "/mnt/daemonica-ittest-missing", Type: "ext4", Options: "defaults"})
	ps, err = disks.Verify(ctx, run, disks.Render(f, broken))
	if err != nil {
		t.Fatal(err)
	}
	if !disks.Blocking(ps) {
		t.Errorf("broken fstab accepted: %+v", ps)
	}
	for _, mp := range []string{"/", "/srv/my-data", "/mnt/a b"} {
		out, err := exec.Command("systemd-escape", "--path", "--suffix=mount", mp).Output()
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.TrimSpace(string(out)); disks.UnitName(mp) != want {
			t.Errorf("%s: %s, systemd-escape %s", mp, disks.UnitName(mp), want)
		}
	}
	if !disks.Mounted("/proc", "/") || len(disks.Users("/proc", "/", 5)) == 0 {
		t.Error("mount table or users of / not found")
	}
}
