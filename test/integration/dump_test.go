//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/services"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
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
	for name, v := range map[string]any{"overview": snap, "services": units, "journal": j, "processes": procs} {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
