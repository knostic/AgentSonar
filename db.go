//go:build darwin || linux

package sai

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	db *sql.DB
}

func DefaultDBPath() string {
	if p := os.Getenv("SAI_DB_PATH"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sai", "sai.db")
}

func OpenDB(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return &DB{db: db}, nil
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY,
		ts DATETIME DEFAULT CURRENT_TIMESTAMP,
		pid INTEGER,
		process TEXT,
		binary_path TEXT,
		domain TEXT,
		source TEXT,
		ja4 TEXT,
		extras JSON
	);
	CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
	CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);
	CREATE INDEX IF NOT EXISTS idx_events_process ON events(process);
	`
	_, err := db.Exec(schema)
	return err
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) InsertEvent(e Event) error {
	extras, _ := json.Marshal(e.Extras)
	_, err := d.db.Exec(`
		INSERT INTO events (ts, pid, process, binary_path, domain, source, ja4, extras)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, e.Timestamp, e.PID, e.Process, e.BinaryPath, e.Domain, e.Source, e.JA4, string(extras))
	return err
}

func (d *DB) QueryEvents(since time.Duration, process, domain string, limit int) ([]Event, error) {
	query := `SELECT ts, pid, process, binary_path, domain, source, ja4, extras FROM events WHERE 1=1`
	var args []any

	if since > 0 {
		query += ` AND ts > ?`
		args = append(args, time.Now().Add(-since))
	}
	if process != "" {
		query += ` AND process LIKE ?`
		args = append(args, "%"+process+"%")
	}
	if domain != "" {
		query += ` AND domain LIKE ?`
		args = append(args, "%"+domain+"%")
	}

	query += ` ORDER BY ts DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var ts time.Time
		var extras string
		if err := rows.Scan(&ts, &e.PID, &e.Process, &e.BinaryPath, &e.Domain, &e.Source, &e.JA4, &extras); err != nil {
			continue
		}
		e.Timestamp = ts
		json.Unmarshal([]byte(extras), &e.Extras)
		events = append(events, e)
	}
	return events, nil
}
