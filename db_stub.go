//go:build !darwin && !linux

package sai

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

var errNoDBSupport = errors.New("database not supported on this platform")

type DB struct{}

func DefaultDBPath() string {
	if p := os.Getenv("SAI_DB_PATH"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sai", "sai.db")
}

func OpenDB(path string) (*DB, error) {
	return nil, errNoDBSupport
}

func (d *DB) Close() error {
	return nil
}

func (d *DB) InsertEvent(e Event) error {
	return errNoDBSupport
}

func (d *DB) QueryEvents(since time.Duration, process, domain string, limit int) ([]Event, error) {
	return nil, errNoDBSupport
}
