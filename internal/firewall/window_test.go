package firewall

import (
	"context"
	"slices"
	"testing"
)

func TestOpenWindow(t *testing.T) {
	ctx := context.Background()
	u, fr := fixture(t)
	write(t, u.Root, ufwBin, "")
	closeFn, err := u.OpenWindow(ctx, 80)
	if err != nil {
		t.Fatal(err)
	}
	open := []string{ufwBin, "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "80", "comment", WindowComment}
	if !slices.Equal(fr.calls[len(fr.calls)-1], open) {
		t.Fatalf("open: %v", fr.calls)
	}
	if err := closeFn(ctx); err != nil {
		t.Fatal(err)
	}
	del := []string{ufwBin, "--force", "delete", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "80"}
	if !slices.Equal(fr.calls[len(fr.calls)-1], del) {
		t.Fatalf("close: %v", fr.calls)
	}

	// Port 22 is open for everyone: nothing to do.
	fr.calls = nil
	if _, err := u.OpenWindow(ctx, 22); err != nil {
		t.Fatal(err)
	}
	for _, c := range fr.calls {
		if len(c) > 1 && c[1] == "allow" {
			t.Fatalf("opened an open port: %v", c)
		}
	}

	// Inactive ufw: nothing to do.
	fr.active, fr.calls = false, nil
	if _, err := u.OpenWindow(ctx, 80); err != nil || len(fr.calls) != 1 {
		t.Fatalf("inactive: %v %v", err, fr.calls)
	}
}

func TestCloseStaleWindows(t *testing.T) {
	u, fr := fixture(t)
	write(t, u.Root, ufwBin, "")
	hex := "6461656d6f6e6963613a61636d653a77696e646f77" // daemonica:acme:window
	write(t, u.Root, userRules, "*filter\n### RULES ###\n\n### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in comment="+hex+
		"\n-A ufw-user-input -p tcp --dport 80 -j ACCEPT\n\n### END RULES ###\n")
	if err := u.CloseStaleWindows(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || !slices.Contains(fr.calls[0], "delete") || fr.calls[0][len(fr.calls[0])-1] != "80" {
		t.Fatalf("calls: %v", fr.calls)
	}
}
