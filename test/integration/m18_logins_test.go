//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/users"
)

// TestLoginHistoryOnHost reads the real wtmpdb/lastlog2 (SPEC §7.2 "letzte
// Anmeldungen", §7.3 "letzte Anmeldung") and expects the SSH session that
// runs the tests to be recorded.
func TestLoginHistoryOnHost(t *testing.T) {
	if _, err := os.Stat(users.WtmpDBPath); err != nil {
		t.Skip("no wtmpdb on this host")
	}
	l := users.LoginDB{Wtmp: users.WtmpDBPath, Lastlog2: users.Lastlog2Path}
	ctx := context.Background()
	recent, err := l.Recent(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	last, err := l.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) == 0 || len(last) == 0 {
		t.Fatalf("no logins recorded: recent %v last %v", recent, last)
	}
	for _, x := range recent {
		t.Logf("%s from %q on %s at %s (end %v)", x.User, x.From, x.TTY, x.Time, x.End)
		if x.Time.IsZero() || last[x.User].Before(x.Time) {
			t.Fatalf("inconsistent: %+v last %v", x, last[x.User])
		}
	}
}
