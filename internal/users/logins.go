package users

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	_ "modernc.org/sqlite" // SQLite driver (wtmpdb, lastlog2)
)

// Ubuntu 25.04+ keeps the login history in SQLite instead of utmp files:
// wtmpdb (every session) and lastlog2 (last login per user).
const (
	WtmpDBPath   = "/var/lib/wtmpdb/wtmp.db"
	Lastlog2Path = "/var/lib/lastlog/lastlog2.db"
)

// userProcess is wtmpdb's record type of a user session (BOOT_TIME = 2).
const userProcess = 3

// Login is one session from the login history.
type Login struct {
	User    string    `json:"user"`
	From    string    `json:"from"`
	TTY     string    `json:"tty"`
	Service string    `json:"service,omitempty"`
	Time    time.Time `json:"time"`
	End     time.Time `json:"end,omitzero"` // zero while the session is open
}

// LoginDB reads wtmpdb and lastlog2 read-only; missing databases are no error.
type LoginDB struct {
	Wtmp     string
	Lastlog2 string
}

func openRO(ctx context.Context, path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func usecTime(v sql.NullInt64) time.Time {
	if !v.Valid || v.Int64 <= 0 {
		return time.Time{}
	}
	return time.UnixMicro(v.Int64).UTC()
}

// Recent returns the n newest user sessions (newest first).
func (l LoginDB) Recent(ctx context.Context, n int) ([]Login, error) {
	out := []Login{}
	db, err := openRO(ctx, l.Wtmp)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(ctx, `SELECT User, Login, Logout, IFNULL(TTY,''), IFNULL(RemoteHost,''), IFNULL(Service,'')
		FROM wtmp WHERE Type = ? ORDER BY Login DESC LIMIT ?`, userProcess, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var x Login
		var in, end sql.NullInt64
		if err := rows.Scan(&x.User, &in, &end, &x.TTY, &x.From, &x.Service); err != nil {
			return nil, err
		}
		x.Time, x.End = usecTime(in), usecTime(end)
		out = append(out, x)
	}
	return out, rows.Err()
}

// Last returns the last login per user: lastlog2 where present, completed by
// wtmpdb (lastlog2 is only written when pam_lastlog2 is enabled).
func (l LoginDB) Last(ctx context.Context) (map[string]time.Time, error) {
	last := map[string]time.Time{}
	keep := func(u string, t time.Time) {
		if !t.IsZero() && t.After(last[u]) {
			last[u] = t
		}
	}
	if db, err := openRO(ctx, l.Lastlog2); err == nil {
		rows, err := db.QueryContext(ctx, `SELECT Name, Time FROM Lastlog2`)
		if err == nil {
			for rows.Next() {
				var u string
				var s sql.NullInt64
				if rows.Scan(&u, &s) == nil && s.Valid && s.Int64 > 0 {
					keep(u, time.Unix(s.Int64, 0).UTC())
				}
			}
			_ = rows.Close()
		}
		_ = db.Close()
	}
	db, err := openRO(ctx, l.Wtmp)
	if errors.Is(err, os.ErrNotExist) {
		return last, nil
	}
	if err != nil {
		return last, err
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(ctx, `SELECT User, MAX(Login) FROM wtmp WHERE Type = ? GROUP BY User`, userProcess)
	if err != nil {
		return last, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var u string
		var in sql.NullInt64
		if err := rows.Scan(&u, &in); err != nil {
			return last, err
		}
		keep(u, usecTime(in))
	}
	return last, rows.Err()
}
