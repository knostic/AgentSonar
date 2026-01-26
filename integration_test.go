//go:build darwin

package sai

import (
	"testing"
	"time"

	"github.com/knostic/sai/internal/capture"
)

func TestKnownAgentFullFlow(t *testing.T) {
	fs := NewOverrides()
	fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})

	registry := NewClassifierRegistry()
	registry.Add(NewDefaultClassifier())

	acc := NewAccumulatorWithOverrides(fs, registry)

	event := Event{
		Timestamp:  time.Now(),
		PID:        1234,
		Process:    "claude-code",
		BinaryPath: "/usr/local/bin/claude",
		Domain:     "api.anthropic.com",
		Source:     "tls",
		Extras: map[string]string{
			"bytes_in":  "50000",
			"bytes_out": "1000",
		},
	}

	acc.Record(event)

	agent := fs.MatchAgent(event.Process, event.Domain)
	if agent != "claude" {
		t.Errorf("agent = %q, want %q", agent, "claude")
	}

	conf := acc.Confidence(event.Process, event.Domain)
	if conf != 1.0 {
		t.Errorf("confidence = %v, want 1.0", conf)
	}
}

func TestNonAIFilterFullFlow(t *testing.T) {
	fs := NewOverrides()
	fs.AddNoise("google.com")

	registry := NewClassifierRegistry()
	registry.Add(NewDefaultClassifier())

	acc := NewAccumulatorWithOverrides(fs, registry)

	event := Event{
		Timestamp: time.Now(),
		PID:       1234,
		Process:   "chrome",
		Domain:    "api.google.com",
		Source:    "tls",
		Extras: map[string]string{
			"bytes_in":    "100000",
			"bytes_out":   "1000",
			"duration_ms": "30000",
		},
	}

	acc.Record(event)

	if !fs.IsNoise(event.Domain) {
		t.Error("domain should be marked as non-AI")
	}

	conf := acc.Confidence(event.Process, event.Domain)
	if conf != 0.0 {
		t.Errorf("confidence = %v, want 0.0 for non-AI domain", conf)
	}
}

func TestUnknownWithAITrafficPattern(t *testing.T) {
	fs := NewOverrides()
	registry := NewClassifierRegistry()
	registry.Add(NewDefaultClassifier())

	acc := NewAccumulatorWithOverrides(fs, registry)

	for i := 0; i < 10; i++ {
		event := Event{
			Timestamp: time.Now(),
			PID:       1234,
			Process:   "suspicious-agent",
			Domain:    "api.unknown-ai.com",
			Source:    "tls",
			Extras: map[string]string{
				"bytes_in":     "50000",
				"bytes_out":    "1000",
				"packets_in":   "500",
				"packets_out":  "10",
				"duration_ms":  "10000",
				"programmatic": "true",
			},
		}
		acc.Record(event)
	}

	event2 := Event{
		Timestamp: time.Now(),
		Process:   "suspicious-agent",
		Domain:    "api.unknown-ai.com",
		Source:    "streaming",
	}
	acc.Record(event2)

	conf := acc.Confidence("suspicious-agent", "api.unknown-ai.com")
	if conf < 0.3 {
		t.Errorf("AI traffic pattern should have confidence >= 0.3, got %v", conf)
	}
	if conf >= 1.0 {
		t.Errorf("unknown agent should not have confidence 1.0, got %v", conf)
	}
}

func TestFilterSetPersistenceFullCycle(t *testing.T) {
	withTempOverrides(t, func(fs *Overrides, path string) {
		fs.AddAgent("openai-agent", "python*", []string{"*.openai.com"})
		fs.AddAgent("claude-agent", "claude*", []string{"*.anthropic.com", "api.anthropic.com"})
		fs.AddNoise("google.com")
		fs.AddNoise("apple.com")
		fs.AddNoise("icloud.com")

		if err := fs.Save(path); err != nil {
			t.Fatalf("Save failed: %v", err)
		}

		loaded := NewOverrides()
		if err := loaded.Load(path); err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		tests := []struct {
			name    string
			process string
			domain  string
			agent   string
		}{
			{"openai match", "python3", "api.openai.com", "openai-agent"},
			{"claude match", "claude-code", "api.anthropic.com", "claude-agent"},
			{"no match", "curl", "example.com", ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := loaded.MatchAgent(tt.process, tt.domain)
				if got != tt.agent {
					t.Errorf("MatchAgent(%q, %q) = %q, want %q", tt.process, tt.domain, got, tt.agent)
				}
			})
		}

		if !loaded.IsNoise("google.com") {
			t.Error("google.com should be non-AI")
		}
		if !loaded.IsNoise("api.apple.com") {
			t.Error("api.apple.com should be non-AI (subdomain)")
		}
	})
}

func TestEventPersistenceAndReplay(t *testing.T) {
	withTempDB(t, func(db *DB) {
		events := []Event{
			{Timestamp: time.Now().Add(-3 * time.Hour), PID: 1, Process: "python3", Domain: "api.openai.com", Source: "tls",
				Extras: map[string]string{"bytes_in": "10000", "bytes_out": "500"}},
			{Timestamp: time.Now().Add(-2 * time.Hour), PID: 2, Process: "python3", Domain: "api.openai.com", Source: "streaming",
				Extras: map[string]string{"bytes_in": "20000", "bytes_out": "100"}},
			{Timestamp: time.Now().Add(-1 * time.Hour), PID: 3, Process: "python3", Domain: "api.openai.com", Source: "tls",
				Extras: map[string]string{"bytes_in": "15000", "bytes_out": "300", "programmatic": "true"}},
		}

		for _, e := range events {
			if err := db.InsertEvent(e); err != nil {
				t.Fatalf("InsertEvent failed: %v", err)
			}
		}

		loaded, err := db.QueryEvents(0, "", "", 0)
		if err != nil {
			t.Fatalf("QueryEvents failed: %v", err)
		}

		fs := NewOverrides()
		fs.AddAgent("openai", "python*", []string{"*.openai.com"})

		registry := NewClassifierRegistry()
		registry.Add(NewDefaultClassifier())

		acc := NewAccumulatorWithOverrides(fs, registry)

		for _, e := range loaded {
			acc.Record(e)
		}

		stats := acc.Stats("python3", "api.openai.com")
		if stats == nil {
			t.Fatal("stats should not be nil")
		}
		if stats.Count != 3 {
			t.Errorf("Count = %d, want 3", stats.Count)
		}
		if stats.Sources["tls"] != 2 {
			t.Errorf("Sources[tls] = %d, want 2", stats.Sources["tls"])
		}
		if stats.Sources["streaming"] != 1 {
			t.Errorf("Sources[streaming] = %d, want 1", stats.Sources["streaming"])
		}
		if stats.TotalBytesIn != 45000 {
			t.Errorf("TotalBytesIn = %d, want 45000", stats.TotalBytesIn)
		}
		if !stats.IsProgrammatic {
			t.Error("should be marked as programmatic")
		}

		conf := acc.Confidence("python3", "api.openai.com")
		if conf != 1.0 {
			t.Errorf("known agent confidence = %v, want 1.0", conf)
		}
	})
}

func TestOverridesHotReload(t *testing.T) {
	withTempOverrides(t, func(_ *Overrides, path string) {
		initial := NewOverrides()
		initial.AddNoise("google.com")
		if err := initial.Save(path); err != nil {
			t.Fatalf("initial save failed: %v", err)
		}

		daemon := NewOverrides()
		if err := daemon.Load(path); err != nil {
			t.Fatalf("daemon load failed: %v", err)
		}

		if !daemon.IsNoise("google.com") {
			t.Fatal("daemon should see initial noise")
		}
		if daemon.IsNoise("facebook.com") {
			t.Fatal("facebook.com should not be noise yet")
		}

		triage := NewOverrides()
		if err := triage.Load(path); err != nil {
			t.Fatalf("triage load failed: %v", err)
		}
		triage.AddNoise("facebook.com")
		if err := triage.Save(path); err != nil {
			t.Fatalf("triage save failed: %v", err)
		}

		if !daemon.IsNoise("facebook.com") {
			t.Error("daemon should see noise added by triage without manual reload")
		}
	})
}

func TestOverridesHotReloadFromNonExistent(t *testing.T) {
	withTempOverrides(t, func(_ *Overrides, path string) {
		daemon := NewOverrides()
		daemon.WatchPath(path)

		if daemon.IsNoise("google.com") {
			t.Fatal("google.com should not be noise initially")
		}

		triage := NewOverrides()
		triage.AddNoise("google.com")
		if err := triage.Save(path); err != nil {
			t.Fatalf("triage save failed: %v", err)
		}

		if !daemon.IsNoise("google.com") {
			t.Error("daemon should see noise created by triage")
		}
	})
}

func TestDNSAndTLSCombined(t *testing.T) {
	queryPkt := makeDNSQueryPacket("api.anthropic.com")
	domain := capture.ParseDNSQuery(queryPkt)
	if domain != "api.anthropic.com" {
		t.Errorf("DNS query domain = %q, want %q", domain, "api.anthropic.com")
	}

	responsePkt := makeDNSResponsePacket("api.anthropic.com", []string{"104.18.1.1", "104.18.2.2"})
	respDomain, ips := capture.ParseDNSResponseIPs(responsePkt)
	if respDomain != "api.anthropic.com" {
		t.Errorf("DNS response domain = %q, want %q", respDomain, "api.anthropic.com")
	}
	if len(ips) != 2 {
		t.Errorf("got %d IPs, want 2", len(ips))
	}

	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	extensions := []uint16{0x0000, 0x0010, 0x000b}
	tlsPkt := makeClientHelloWithALPN("api.anthropic.com", ciphers, extensions, "h2")

	ch := capture.ParseClientHello(tlsPkt)
	if ch == nil {
		t.Fatal("ParseClientHello returned nil")
	}
	if ch.SNI != "api.anthropic.com" {
		t.Errorf("TLS SNI = %q, want %q", ch.SNI, "api.anthropic.com")
	}

	fs := NewOverrides()
	fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})

	if fs.MatchAgent("claude-code", domain) != "claude" {
		t.Error("should match claude agent via DNS domain")
	}
	if fs.MatchAgent("claude-code", ch.SNI) != "claude" {
		t.Error("should match claude agent via TLS SNI")
	}
}
