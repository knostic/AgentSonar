//go:build darwin

package sai

import (
	"path/filepath"
	"testing"
)

func withTempDB(t *testing.T, fn func(db *DB)) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer db.Close()
	fn(db)
}
