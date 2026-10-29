package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestMigrateBackupAndNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	v1 := fstest.MapFS{"0001_init.sql": {Data: []byte("CREATE TABLE a(x INTEGER);")}}
	db, err := Open(ctx, path, v1)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	v2 := fstest.MapFS{"0001_init.sql": v1["0001_init.sql"], "0002_more.sql": {Data: []byte("CREATE TABLE b(y INTEGER);")}}
	db, err = Open(ctx, path, v2)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	baks, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "db.sqlite.*.bak"))
	if len(baks) != 1 {
		t.Fatalf("backups %v", baks)
	}
	if fi, err := os.Stat(baks[0]); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v %v", fi, err)
	}

	// Downgrade: the older release refuses the newer database.
	if _, err := Open(ctx, path, v1); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("downgrade: %v", err)
	}
}
