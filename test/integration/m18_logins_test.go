//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/users"
)

// TestLoginHistoryOnHost reads the real wtmpdb/lastlog2 (SPEC §7.2 "letzte
// Anmeldungen", §7.3 "letzte Anmeldung") and expects the SSH session that
// runs the tests to be recorded (wtmpdb, or sshd's journal where wtmpdb is missing).
func TestLoginHistoryOnHost(t *testing.T) {
	// Without wtmpdb (Ubuntu 26.04 without pam_wtmpdb) the history comes from
	// sshd's journal lines, as in the helper.
	l := users.LoginDB{Wtmp: users.WtmpDBPath, Lastlog2: users.Lastlog2Path, Journal: func(ctx context.Context) ([]users.LogLine, error) {
		var out []users.LogLine
		for _, grep := range []string{"Accepted ", "Disconnected from user ", "session closed for user "} {
			res, err := journal.Run(ctx, journal.Query{Unit: "ssh.service", Grep: grep, Lines: 500})
			if err != nil {
				return nil, err
			}
			for _, e := range res.Entries {
				out = append(out, users.LogLine{Time: e.Time, PID: e.PID, Message: e.Message})
			}
		}
		return out, nil
	}}
	if _, err := os.Stat(users.WtmpDBPath); err != nil {
		t.Log("no wtmpdb on this host: reading sshd's journal")
	}
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
