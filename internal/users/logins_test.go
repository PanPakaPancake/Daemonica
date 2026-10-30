package users

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestLoginDB(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l := LoginDB{Wtmp: filepath.Join(dir, "wtmp.db"), Lastlog2: filepath.Join(dir, "lastlog2.db")}
	if got, err := l.Recent(ctx, 5); err != nil || len(got) != 0 {
		t.Fatalf("missing db: %v %v", got, err)
	}
	t0 := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	w, err := sql.Open("sqlite", "file:"+l.Wtmp)
	if err != nil {
		t.Fatal(err)
	}
	mustExec := func(db *sql.DB, q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(w, `CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT NOT NULL, Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)`)
	mustExec(w, `INSERT INTO wtmp(Type,User,Login,Logout,TTY,RemoteHost,Service) VALUES
		(2,'reboot',?,NULL,'~','6.18.0',NULL),
		(3,'pancake',?,?,'pts/0','37.201.167.99','sshd'),
		(3,'root',?,NULL,'pts/1','37.201.167.99','sshd'),
		(3,'pancake',?,NULL,'pts/2',NULL,'login')`,
		t0.UnixMicro(), t0.Add(time.Minute).UnixMicro(), t0.Add(time.Hour).UnixMicro(), t0.Add(2*time.Minute).UnixMicro(), t0.Add(3*time.Minute).UnixMicro())
	_ = w.Close()
	ll, _ := sql.Open("sqlite", "file:"+l.Lastlog2)
	mustExec(ll, `CREATE TABLE Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)`)
	mustExec(ll, `INSERT INTO Lastlog2 VALUES ('root', ?, 'pts/1', '', 'sshd'), ('alice', ?, 'tty1', '', 'login')`, t0.Add(-time.Hour).Unix(), t0.Add(-48*time.Hour).Unix())
	_ = ll.Close()

	got, err := l.Recent(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].User != "pancake" || got[0].TTY != "pts/2" || !got[0].End.IsZero() || got[1].User != "root" || got[1].From != "37.201.167.99" {
		t.Fatalf("recent %+v", got)
	}
	last, err := l.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !last["pancake"].Equal(t0.Add(3*time.Minute)) || !last["root"].Equal(t0.Add(2*time.Minute)) || !last["alice"].Equal(t0.Add(-48*time.Hour)) || len(last) != 3 {
		t.Fatalf("last %v", last)
	}
}

func TestSSHLoginsFromJournal(t *testing.T) {
	t0 := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	lines := []LogLine{
		{Time: t0.Add(5 * time.Minute), PID: 12, Message: "pam_unix(sshd:session): session closed for user pancake"},
		{Time: t0.Add(6 * time.Minute), PID: 12, Message: "Disconnected from user pancake 203.0.113.7 port 50000"},
		{Time: t0, PID: 12, Message: "Accepted publickey for pancake from 203.0.113.7 port 50000 ssh2: ED25519 SHA256:abc"},
		{Time: t0.Add(time.Minute), PID: 13, Message: "Accepted password for op from 2001:db8::5 port 41000 ssh2"},
		{Time: t0.Add(2 * time.Minute), PID: 14, Message: "Accepted publickey for leser from 198.51.100.4 port 1 ssh2"},
		{Time: t0.Add(3 * time.Minute), PID: 15, Message: "Failed password for root from 192.0.2.1 port 2 ssh2"},
	}
	got := SSHLogins(lines, func(pid int) bool { return pid == 13 })
	if len(got) != 3 || got[0].User != "leser" || got[1].User != "op" || got[2].User != "pancake" {
		t.Fatalf("order/users: %+v", got)
	}
	if !got[0].End.Equal(got[0].Time) || !got[1].End.IsZero() || !got[2].End.Equal(t0.Add(5*time.Minute)) {
		t.Fatalf("ends: %+v", got)
	}
	if got[1].From != "2001:db8::5" || got[1].TTY != "ssh" {
		t.Fatalf("fields: %+v", got[1])
	}
	// Without wtmpdb the database falls back to the journal.
	l := LoginDB{Wtmp: filepath.Join(t.TempDir(), "none.db"), Lastlog2: filepath.Join(t.TempDir(), "none2.db"),
		Journal: func(context.Context) ([]LogLine, error) { return lines, nil }}
	ctx := context.Background()
	if r, err := l.Recent(ctx, 2); err != nil || len(r) != 2 || r[0].User != "leser" {
		t.Fatalf("recent: %+v %v", r, err)
	}
	if last, err := l.Last(ctx); err != nil || !last["pancake"].Equal(t0) || len(last) != 3 {
		t.Fatalf("last: %v %v", last, err)
	}
}
