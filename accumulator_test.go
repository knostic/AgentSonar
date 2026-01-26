package sai

import (
	"testing"
	"time"
)

func TestAccumulatorRecordsStats(t *testing.T) {
	acc := NewAccumulator()

	event := makeEvent("curl", "api.openai.com", "tls")
	acc.Record(event)

	if acc.Count("curl", "api.openai.com") != 1 {
		t.Error("count should be 1 after recording")
	}

	acc.Record(event)
	acc.Record(event)

	if acc.Count("curl", "api.openai.com") != 3 {
		t.Error("count should be 3 after recording 3 times")
	}

	stats := acc.Stats("curl", "api.openai.com")
	if stats == nil {
		t.Fatal("stats should not be nil")
	}
	if stats.Count != 3 {
		t.Errorf("stats.Count = %d, want 3", stats.Count)
	}
	if stats.Sources["tls"] != 3 {
		t.Errorf("stats.Sources[tls] = %d, want 3", stats.Sources["tls"])
	}
}

func TestAccumulatorExtractsExtras(t *testing.T) {
	acc := NewAccumulator()

	event := makeEventWithExtras("curl", "api.openai.com", map[string]string{
		"bytes_in":    "1000",
		"bytes_out":   "500",
		"packets_in":  "100",
		"packets_out": "50",
		"duration_ms": "5000",
		"concurrent":  "3",
		"programmatic": "true",
	})
	acc.Record(event)

	stats := acc.Stats("curl", "api.openai.com")
	if stats == nil {
		t.Fatal("stats should not be nil")
	}

	if stats.TotalBytesIn != 1000 {
		t.Errorf("TotalBytesIn = %d, want 1000", stats.TotalBytesIn)
	}
	if stats.TotalBytesOut != 500 {
		t.Errorf("TotalBytesOut = %d, want 500", stats.TotalBytesOut)
	}
	if stats.TotalPacketsIn != 100 {
		t.Errorf("TotalPacketsIn = %d, want 100", stats.TotalPacketsIn)
	}
	if stats.TotalPacketsOut != 50 {
		t.Errorf("TotalPacketsOut = %d, want 50", stats.TotalPacketsOut)
	}
	if stats.TotalDurationMs != 5000 {
		t.Errorf("TotalDurationMs = %d, want 5000", stats.TotalDurationMs)
	}
	if stats.MaxConcurrent != 3 {
		t.Errorf("MaxConcurrent = %d, want 3", stats.MaxConcurrent)
	}
	if !stats.IsProgrammatic {
		t.Error("IsProgrammatic should be true")
	}
}

func TestKnownAgentReturnsOne(t *testing.T) {
	fs := NewOverrides()
	fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})

	acc := NewAccumulatorWithOverrides(fs, NewClassifierRegistry())

	event := makeEvent("claude-code", "api.anthropic.com", "tls")
	acc.Record(event)

	conf := acc.Confidence("claude-code", "api.anthropic.com")
	if conf != 1.0 {
		t.Errorf("known agent confidence = %v, want 1.0", conf)
	}
}

func TestNonAIReturnsZero(t *testing.T) {
	fs := NewOverrides()
	fs.AddNoise("google.com")

	acc := NewAccumulatorWithOverrides(fs, NewClassifierRegistry())

	event := makeEvent("chrome", "google.com", "tls")
	acc.Record(event)

	conf := acc.Confidence("chrome", "google.com")
	if conf != 0.0 {
		t.Errorf("non-AI confidence = %v, want 0.0", conf)
	}
}

func TestHeuristicScoreFromRegistry(t *testing.T) {
	fs := NewOverrides()
	registry := NewClassifierRegistry()
	registry.Add(NewDefaultClassifier())

	acc := NewAccumulatorWithOverrides(fs, registry)

	event := makeEventWithExtras("unknown", "api.example.com", map[string]string{
		"bytes_in":    "100000",
		"bytes_out":   "1000",
		"packets_in":  "1000",
		"packets_out": "10",
		"duration_ms": "10000",
	})
	acc.Record(event)

	conf := acc.Confidence("unknown", "api.example.com")
	if conf <= 0 {
		t.Errorf("heuristic confidence should be > 0, got %v", conf)
	}
}

func TestConfidenceCappedAt099(t *testing.T) {
	fs := NewOverrides()
	registry := NewClassifierRegistry()
	registry.Add(&mockClassifier{name: "high", conf: 1.5})

	acc := NewAccumulatorWithOverrides(fs, registry)

	event := makeEvent("test", "example.com", "tls")
	acc.Record(event)

	conf := acc.Confidence("test", "example.com")
	if conf > 0.99 {
		t.Errorf("heuristic confidence should be capped at 0.99, got %v", conf)
	}
}

func TestStatsCopied(t *testing.T) {
	acc := NewAccumulator()

	event := makeEvent("curl", "api.openai.com", "tls")
	acc.Record(event)

	stats1 := acc.Stats("curl", "api.openai.com")
	stats2 := acc.Stats("curl", "api.openai.com")

	stats1.Count = 999
	stats1.Sources["modified"] = 1

	if stats2.Count == 999 {
		t.Error("modifying returned stats should not affect internal state")
	}
	if stats2.Sources["modified"] == 1 {
		t.Error("modifying returned sources map should not affect internal state")
	}
}

func TestAccumulatorReset(t *testing.T) {
	acc := NewAccumulator()

	event := makeEvent("curl", "api.openai.com", "tls")
	acc.Record(event)

	if acc.Count("curl", "api.openai.com") != 1 {
		t.Error("count should be 1")
	}

	acc.Reset()

	if acc.Count("curl", "api.openai.com") != 0 {
		t.Error("count should be 0 after reset")
	}
	if acc.Stats("curl", "api.openai.com") != nil {
		t.Error("stats should be nil after reset")
	}
}

func TestAccumulatorDomainNormalization(t *testing.T) {
	acc := NewAccumulator()

	acc.Record(makeEvent("curl", "WWW.EXAMPLE.COM", "tls"))
	acc.Record(makeEvent("curl", "www.example.com", "tls"))
	acc.Record(makeEvent("curl", "example.com", "tls"))

	if acc.Count("curl", "example.com") != 3 {
		t.Error("all normalized domains should accumulate to same key")
	}
}

func TestAccumulatorNoStats(t *testing.T) {
	acc := NewAccumulator()

	stats := acc.Stats("nonexistent", "nowhere.com")
	if stats != nil {
		t.Error("stats for non-recorded pair should be nil")
	}

	count := acc.Count("nonexistent", "nowhere.com")
	if count != 0 {
		t.Error("count for non-recorded pair should be 0")
	}
}

func TestAccumulatorFirstLastSeen(t *testing.T) {
	acc := NewAccumulator()

	first := time.Now()
	event1 := Event{Timestamp: first, Process: "curl", Domain: "example.com", Source: "tls"}
	acc.Record(event1)

	later := first.Add(time.Hour)
	event2 := Event{Timestamp: later, Process: "curl", Domain: "example.com", Source: "tls"}
	acc.Record(event2)

	stats := acc.Stats("curl", "example.com")
	if !stats.FirstSeen.Equal(first) {
		t.Errorf("FirstSeen = %v, want %v", stats.FirstSeen, first)
	}
	if !stats.LastSeen.Equal(later) {
		t.Errorf("LastSeen = %v, want %v", stats.LastSeen, later)
	}
}

type mockSignals struct {
	agents   map[string]string
	nonAI    map[string]bool
	nonAIDom map[string]bool
}

func (m *mockSignals) MatchAgent(process, domain string) string {
	return m.agents[process+":"+domain]
}

func (m *mockSignals) IsNonAI(process, domain string) bool {
	return m.nonAI[process+":"+domain]
}

func (m *mockSignals) IsNonAIDomain(domain string) bool {
	return m.nonAIDom[domain]
}

func TestCustomSignalsImplementation(t *testing.T) {
	signals := &mockSignals{
		agents:   map[string]string{"claude-code:api.anthropic.com": "claude"},
		nonAI:    map[string]bool{},
		nonAIDom: map[string]bool{"google.com": true},
	}

	acc := NewAccumulatorWithSignals(signals, NewClassifierRegistry())

	event := makeEvent("claude-code", "api.anthropic.com", "tls")
	acc.Record(event)

	conf := acc.Confidence("claude-code", "api.anthropic.com")
	if conf != 1.0 {
		t.Errorf("custom signals agent confidence = %v, want 1.0", conf)
	}

	event2 := makeEvent("chrome", "google.com", "tls")
	acc.Record(event2)

	conf2 := acc.Confidence("chrome", "google.com")
	if conf2 != 0.0 {
		t.Errorf("custom signals non-AI confidence = %v, want 0.0", conf2)
	}
}
