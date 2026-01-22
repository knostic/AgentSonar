//go:build darwin

package sai

import (
	"testing"
	"time"
)

func TestDBInsertAndQuery(t *testing.T) {
	withTempDB(t, func(db *DB) {
		events := []Event{
			{
				Timestamp:  time.Now().Add(-2 * time.Hour),
				PID:        100,
				Process:    "curl",
				BinaryPath: "/usr/bin/curl",
				Domain:     "api.openai.com",
				Source:     "tls",
			},
			{
				Timestamp:  time.Now().Add(-1 * time.Hour),
				PID:        101,
				Process:    "python3",
				BinaryPath: "/usr/bin/python3",
				Domain:     "api.anthropic.com",
				Source:     "tls",
			},
		}

		for _, e := range events {
			if err := db.InsertEvent(e); err != nil {
				t.Fatalf("InsertEvent failed: %v", err)
			}
		}

		results, err := db.QueryEvents(0, "", "", 0)
		if err != nil {
			t.Fatalf("QueryEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("got %d events, want 2", len(results))
		}

		if results[0].Domain != "api.anthropic.com" {
			t.Error("results should be ordered by timestamp DESC")
		}
	})
}

func TestDBQueryFilters(t *testing.T) {
	withTempDB(t, func(db *DB) {
		events := []Event{
			{Timestamp: time.Now(), PID: 1, Process: "curl", Domain: "api.openai.com", Source: "tls"},
			{Timestamp: time.Now(), PID: 2, Process: "python3", Domain: "api.openai.com", Source: "tls"},
			{Timestamp: time.Now(), PID: 3, Process: "curl", Domain: "api.anthropic.com", Source: "tls"},
			{Timestamp: time.Now().Add(-2 * time.Hour), PID: 4, Process: "wget", Domain: "example.com", Source: "dns"},
		}

		for _, e := range events {
			db.InsertEvent(e)
		}

		results, _ := db.QueryEvents(0, "curl", "", 0)
		if len(results) != 2 {
			t.Errorf("process filter: got %d, want 2", len(results))
		}

		results, _ = db.QueryEvents(0, "", "openai", 0)
		if len(results) != 2 {
			t.Errorf("domain filter: got %d, want 2", len(results))
		}

		results, _ = db.QueryEvents(0, "curl", "anthropic", 0)
		if len(results) != 1 {
			t.Errorf("combined filter: got %d, want 1", len(results))
		}

		results, _ = db.QueryEvents(1*time.Hour, "", "", 0)
		if len(results) != 3 {
			t.Errorf("since filter: got %d, want 3", len(results))
		}
	})
}

func TestDBQueryLimit(t *testing.T) {
	withTempDB(t, func(db *DB) {
		for i := 0; i < 10; i++ {
			db.InsertEvent(Event{
				Timestamp: time.Now().Add(time.Duration(-i) * time.Minute),
				PID:       i,
				Process:   "test",
				Domain:    "example.com",
				Source:    "tls",
			})
		}

		results, _ := db.QueryEvents(0, "", "", 5)
		if len(results) != 5 {
			t.Errorf("limit: got %d, want 5", len(results))
		}

		if results[0].Timestamp.After(results[4].Timestamp) == false {
			t.Error("results should be ordered by timestamp DESC")
		}
	})
}

func TestDBExtrasRoundTrip(t *testing.T) {
	withTempDB(t, func(db *DB) {
		event := Event{
			Timestamp: time.Now(),
			PID:       123,
			Process:   "test",
			Domain:    "example.com",
			Source:    "tls",
			JA4:       "t13d1234_abc_xyz",
			Extras: map[string]string{
				"bytes_in":    "1000",
				"bytes_out":   "500",
				"duration_ms": "5000",
				"custom_key":  "custom_value",
			},
		}

		if err := db.InsertEvent(event); err != nil {
			t.Fatalf("InsertEvent failed: %v", err)
		}

		results, _ := db.QueryEvents(0, "", "", 1)
		if len(results) != 1 {
			t.Fatal("expected 1 result")
		}

		got := results[0]
		if got.JA4 != event.JA4 {
			t.Errorf("JA4 = %q, want %q", got.JA4, event.JA4)
		}

		if got.Extras == nil {
			t.Fatal("Extras is nil")
		}

		if got.Extras["bytes_in"] != "1000" {
			t.Errorf("bytes_in = %q, want %q", got.Extras["bytes_in"], "1000")
		}
		if got.Extras["custom_key"] != "custom_value" {
			t.Errorf("custom_key = %q, want %q", got.Extras["custom_key"], "custom_value")
		}
	})
}

func TestDBEmptyExtras(t *testing.T) {
	withTempDB(t, func(db *DB) {
		event := Event{
			Timestamp: time.Now(),
			PID:       123,
			Process:   "test",
			Domain:    "example.com",
			Source:    "tls",
		}

		if err := db.InsertEvent(event); err != nil {
			t.Fatalf("InsertEvent failed: %v", err)
		}

		results, _ := db.QueryEvents(0, "", "", 1)
		if len(results) != 1 {
			t.Fatal("expected 1 result")
		}
	})
}
