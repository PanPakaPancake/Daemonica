//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/firewall"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
)

// TestACMEWindow opens and closes the ACME window on an unused port with the
// real ufw (SPEC §3.6) and checks that a left-over window is cleaned up.
// It changes the firewall for a moment: run it on the acceptance VM only.
func TestACMEWindow(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("DAEMONICA_FIREWALL_TESTS") != "1" {
		t.Skip("needs root and DAEMONICA_FIREWALL_TESTS=1")
	}
	ctx := context.Background()
	u := &firewall.Ufw{Run: netcfg.ExecRunner}
	if active, err := u.Active(ctx); err != nil || !active {
		t.Skip("ufw not active")
	}
	const port = 47123
	has := func() bool {
		c, err := u.ReadConfig()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range c.Rules {
			if r.Comment == firewall.WindowComment && r.DPort == "47123" {
				return true
			}
		}
		return false
	}
	closeFn, err := u.OpenWindow(ctx, port)
	if err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Fatal("window rule missing")
	}
	if err := closeFn(ctx); err != nil {
		t.Fatal(err)
	}
	if has() {
		t.Fatal("window rule still there")
	}
	if _, err := u.OpenWindow(ctx, port); err != nil {
		t.Fatal(err)
	}
	if err := u.CloseStaleWindows(ctx); err != nil {
		t.Fatal(err)
	}
	if has() {
		t.Fatal("stale window not removed")
	}
}
