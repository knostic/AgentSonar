//go:build darwin

package sai

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	db *sql.DB
}

func DefaultDBPath() string {
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

	CREATE TABLE IF NOT EXISTS agents (
		id INTEGER PRIMARY KEY,
		name TEXT UNIQUE,
		process_pattern TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS agent_domains (
		id INTEGER PRIMARY KEY,
		agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
		domain_pattern TEXT,
		added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(agent_id, domain_pattern)
	);
	CREATE INDEX IF NOT EXISTS idx_agent_domains_agent ON agent_domains(agent_id);

	CREATE TABLE IF NOT EXISTS ignored (
		id INTEGER PRIMARY KEY,
		url TEXT UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
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

func (d *DB) AddAgent(name, processPattern string) error {
	_, err := d.db.Exec(`INSERT INTO agents (name, process_pattern) VALUES (?, ?)`, name, processPattern)
	return err
}

func (d *DB) AddAgentDomain(agentName, domainPattern string) error {
	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO agent_domains (agent_id, domain_pattern)
		SELECT id, ? FROM agents WHERE name = ?
	`, domainPattern, agentName)
	return err
}

func (d *DB) ListAgents() ([]Agent, error) {
	rows, err := d.db.Query(`SELECT id, name, process_pattern FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.ProcessPattern); err != nil {
			continue
		}
		// Get domains
		domRows, err := d.db.Query(`SELECT domain_pattern FROM agent_domains WHERE agent_id = ?`, a.ID)
		if err == nil {
			for domRows.Next() {
				var dom string
				domRows.Scan(&dom)
				a.Domains = append(a.Domains, dom)
			}
			domRows.Close()
		}
		agents = append(agents, a)
	}
	return agents, nil
}

func (d *DB) GetAgent(name string) (*Agent, error) {
	var a Agent
	err := d.db.QueryRow(`SELECT id, name, process_pattern FROM agents WHERE name = ?`, name).Scan(&a.ID, &a.Name, &a.ProcessPattern)
	if err != nil {
		return nil, err
	}

	rows, err := d.db.Query(`SELECT domain_pattern FROM agent_domains WHERE agent_id = ?`, a.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dom string
			rows.Scan(&dom)
			a.Domains = append(a.Domains, dom)
		}
	}
	return &a, nil
}

func (d *DB) DeleteAgent(name string) error {
	_, err := d.db.Exec(`DELETE FROM agents WHERE name = ?`, name)
	return err
}

func (d *DB) AddIgnore(url string) error {
	_, err := d.db.Exec(`INSERT OR IGNORE INTO ignored (url) VALUES (?)`, url)
	return err
}

func (d *DB) ListIgnored() ([]IgnoreRule, error) {
	rows, err := d.db.Query(`SELECT id, url FROM ignored ORDER BY url`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []IgnoreRule
	for rows.Next() {
		var r IgnoreRule
		if err := rows.Scan(&r.ID, &r.URL); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (d *DB) RemoveIgnore(url string) error {
	_, err := d.db.Exec(`DELETE FROM ignored WHERE url = ?`, url)
	return err
}

func (d *DB) MatchAgent(process, domain string) string {
	process = strings.ToLower(process)
	domain = strings.ToLower(domain)

	rows, err := d.db.Query(`
		SELECT a.name, a.process_pattern, ad.domain_pattern
		FROM agents a
		JOIN agent_domains ad ON ad.agent_id = a.id
	`)
	if err != nil {
		return ""
	}
	defer rows.Close()

	for rows.Next() {
		var name, procPattern, domPattern string
		if err := rows.Scan(&name, &procPattern, &domPattern); err != nil {
			continue
		}
		if matchPattern(process, strings.ToLower(procPattern)) && matchPattern(domain, strings.ToLower(domPattern)) {
			return name
		}
	}
	return ""
}

func (d *DB) IsIgnored(domain string) bool {
	domain = strings.ToLower(domain)

	rows, err := d.db.Query(`SELECT url FROM ignored`)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			continue
		}
		if matchPattern(domain, strings.ToLower(url)) {
			return true
		}
	}
	return false
}

func matchPattern(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(s, pattern[1:]) || s == pattern[2:]
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return s == pattern || strings.Contains(s, pattern)
}

func (d *DB) GetUntriagedEvents(limit int) ([]Event, error) {
	query := `
		SELECT DISTINCT e.ts, e.pid, e.process, e.binary_path, e.domain, e.source, e.ja4, e.extras
		FROM events e
		WHERE NOT EXISTS (
			SELECT 1 FROM agents a
			JOIN agent_domains ad ON ad.agent_id = a.id
			WHERE e.process LIKE '%' || a.process_pattern || '%'
			  AND e.domain LIKE '%' || REPLACE(REPLACE(ad.domain_pattern, '*.', ''), '*', '') || '%'
		)
		AND NOT EXISTS (
			SELECT 1 FROM ignored i
			WHERE e.domain LIKE '%' || REPLACE(REPLACE(i.url, '*.', ''), '*', '') || '%'
		)
		ORDER BY e.ts DESC
	`
	if limit > 0 {
		query += ` LIMIT ?`
	}

	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = d.db.Query(query, limit)
	} else {
		rows, err = d.db.Query(query)
	}
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
