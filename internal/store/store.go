// Package store opens SQLite databases with the settings mandated by SPEC
// §4.1 (WAL, foreign keys, busy timeout) and applies embedded, forward-only
// migrations, taking a backup before each migration run.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // CGO-free SQLite driver (DEC-012)
)

// Open opens (or creates) the database at path with mode 0600 and migrates it
// using the *.sql files in migrations (named NNNN_description.sql).
func Open(ctx context.Context, path string, migrations fs.FS) (*sql.DB, error) {
	if err := ensureFile(path); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // serialize writers; SQLite is single-writer anyway
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrate(ctx, db, path, migrations); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func ensureFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // fixed path
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations(m fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(m, ".")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("store: bad migration name %q", e.Name())
		}
		b, err := fs.ReadFile(m, e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, errors.New("store: duplicate migration version")
		}
	}
	return out, nil
}

func migrate(ctx context.Context, db *sql.DB, path string, m fs.FS) error {
	all, err := loadMigrations(m)
	if err != nil {
		return err
	}
	var current int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return err
	}
	var pending []migration
	for _, mg := range all {
		if mg.version > current {
			pending = append(pending, mg)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if current > 0 {
		if err := backup(ctx, db, path); err != nil {
			return fmt.Errorf("store: pre-migration backup failed: %w", err)
		}
	}
	for _, mg := range pending {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, mg.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", mg.name, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", mg.version)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// backup writes a consistent copy next to the database (VACUUM INTO).
func backup(ctx context.Context, db *sql.DB, path string) error {
	dir := filepath.Join(filepath.Dir(path), "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(dir, filepath.Base(path)+"."+time.Now().UTC().Format("20060102T150405Z")+".bak")
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}
