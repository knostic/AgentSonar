//go:build !darwin && !linux

package sai

import (
	"errors"
	"time"
)

var errNoDBSupport = errors.New("database not supported on this platform")

type DB struct{}

func DefaultDBPath() string {
	if p := resolveLegacyEnvDB(); p != "" {
		return p
	}
	return defaultDBPathNew()
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
