//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/services"
	"github.com/PanPakaPancake/daemonica/internal/sshkeys"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
	"github.com/PanPakaPancake/daemonica/internal/users"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// TestDumpFixtures writes real host data as JSON for UI screenshot fixtures
// (only when DUMP_DIR is set). The files never leave the test VM unreviewed.
func TestDumpFixtures(t *testing.T) {
	dir := os.Getenv("DUMP_DIR")
	if dir == "" {
		t.Skip("DUMP_DIR not set")
	}
	ctx := context.Background()
	c := &sysinfo.Collector{FS: sysinfo.FS{Root: "/"}}
	c.Sample(ctx)
	time.Sleep(time.Second)
	c.Sample(ctx)
	sd, err := services.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sd.Close() }()
	units, _ := sd.List(ctx)
	j, _ := journal.Run(ctx, journal.Query{Lines: 200})
	procs := map[string]any{"processes": c.Processes(), "truncated": false}
	n, _ := sd.FailedCount(ctx)
	snap := c.Snapshot()
	snap.FailedUnits = &n
	days := 89
	snap.CertDays = &days
	ops := map[string]*helper.Op{}
	(&helper.UserOps{DB: users.DB{Root: "/"}}).Register(ops)
	ko := &helper.SSHKeyOps{Worker: &worker.Runner{Timeout: 20 * time.Second}, Lookup: worker.Lookup, Config: sshkeys.EffectiveConfig, HostKeyDir: "/etc/ssh"}
	ko.Register(ops)
	admin := policy.Subject{AccountID: "it", Role: policy.RoleAdmin, LinuxUID: 1000, StepUp: true}
	call := func(op string, p any) any {
		v, err := ops[op].Handle(ctx, helper.Call{Subject: &admin, Params: mustJSON(p)})
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return v
	}
	ul := call("users.list", map[string]any{})
	kl := call("sshkeys.list", map[string]any{"user": "pancake"})
	srv := call("sshkeys.server", map[string]any{})
	for name, v := range map[string]any{"overview": snap, "services": units, "journal": j, "processes": procs, "users": ul, "sshkeys": kl, "sshserver": srv} {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
