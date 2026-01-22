//go:build darwin

package sai

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Accumulator tracks events and computes confidence for process:domain pairs
type Accumulator interface {
	Record(event Event)
	Confidence(process, domain string) Confidence
	Count(process, domain string) int
	Stats(process, domain string) *PairStats
}

// PairStats holds accumulated statistics for a process:domain pair
type PairStats struct {
	Process         string
	Domain          string
	Count           int
	FirstSeen       time.Time
	LastSeen        time.Time
	Sources         map[string]int // tls, dns, streaming counts
	IsProgrammatic  bool
	TotalBytesIn    int64
	TotalBytesOut   int64
	TotalPacketsIn  int
	TotalPacketsOut int
	TotalDurationMs int64
	MaxConcurrent   int
	BaseConfidence  Confidence // from classifier
}

// MemoryAccumulator is an in-memory Accumulator implementation
type MemoryAccumulator struct {
	classifier *Classifier
	pairs      map[string]*PairStats
	mu         sync.RWMutex
}

func NewAccumulator() *MemoryAccumulator {
	return &MemoryAccumulator{
		classifier: NewClassifier(),
		pairs:      make(map[string]*PairStats),
	}
}

func (a *MemoryAccumulator) Record(event Event) {
	key := event.Process + ":" + normalizeDomain(event.Domain)

	a.mu.Lock()
	defer a.mu.Unlock()

	stats, ok := a.pairs[key]
	if !ok {
		stats = &PairStats{
			Process:   event.Process,
			Domain:    event.Domain,
			FirstSeen: event.Timestamp,
			Sources:   make(map[string]int),
		}
		stats.BaseConfidence = a.classifyDomain(event.Domain)
		a.pairs[key] = stats
	}

	stats.Count++
	stats.LastSeen = event.Timestamp
	stats.Sources[event.Source]++

	if event.Extras != nil {
		if event.Extras["programmatic"] == "true" {
			stats.IsProgrammatic = true
		}
		if b, err := strconv.ParseInt(event.Extras["bytes_in"], 10, 64); err == nil {
			stats.TotalBytesIn += b
		}
		if b, err := strconv.ParseInt(event.Extras["bytes_out"], 10, 64); err == nil {
			stats.TotalBytesOut += b
		}
		if p, err := strconv.Atoi(event.Extras["packets_in"]); err == nil {
			stats.TotalPacketsIn += p
		}
		if p, err := strconv.Atoi(event.Extras["packets_out"]); err == nil {
			stats.TotalPacketsOut += p
		}
		if d, err := strconv.ParseInt(event.Extras["duration_ms"], 10, 64); err == nil {
			stats.TotalDurationMs += d
		}
		if c, err := strconv.Atoi(event.Extras["concurrent"]); err == nil && c > stats.MaxConcurrent {
			stats.MaxConcurrent = c
		}
	}
}

var infrastructurePenalties = map[string]Confidence{
	// Logging/observability - very unlikely to be LLM traffic
	"logs":      0.5,
	"log":       0.5,
	"logging":   0.5,
	"telemetry": 0.5,
	"metrics":   0.4,
	"intake":    0.4,

	// Analytics/tracking/experimentation
	"analytics": 0.4,
	"tracking":  0.4,
	"tracker":   0.4,
	"statsig":   0.4,
	"events":    0.3,

	// Infrastructure
	"cdn":        0.3,
	"static":     0.3,
	"assets":     0.3,
	"media":      0.3,
	"gateway":    0.3,
	"cloudkit":       0.4,
	"apple-cloudkit": 0.4,
	"cloudfront":     0.4,
	"cloudflare":     0.4,
	"akamai":         0.4,
	"fastly":         0.4,
	"icloud":         0.4,

	// Status/health
	"stats":  0.3,
	"status": 0.3,
	"health": 0.3,

	// Auth/security (rarely LLM endpoints)
	"auth":   0.2,
	"oauth":  0.2,
	"oauth2": 0.2,
	"login":  0.2,
	"sso":    0.2,
	"ocsp":  0.5,
	"ocsp2": 0.5,
	"crl":   0.5,
}

func infrastructurePenalty(domain string) Confidence {
	var totalPenalty Confidence
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if penalty, ok := infrastructurePenalties[part]; ok {
			totalPenalty += penalty
		}
	}
	return totalPenalty
}

func (a *MemoryAccumulator) classifyDomain(domain string) Confidence {
	domain = normalizeDomain(domain)

	if a.classifier.aiFilter.Test(domain) {
		return 0.9
	}
	if a.classifier.IsAI(domain) {
		return 0.6
	}
	return 0.0
}

func (a *MemoryAccumulator) Confidence(process, domain string) Confidence {
	key := process + ":" + normalizeDomain(domain)

	a.mu.RLock()
	defer a.mu.RUnlock()

	stats, ok := a.pairs[key]
	if !ok {
		conf := a.classifyDomain(domain) - infrastructurePenalty(domain)
		if conf < 0 {
			return 0
		}
		return conf
	}

	conf := stats.BaseConfidence

	// Derive ratios from raw data
	var byteRatio, packetRatio, avgPacketSize, packetsPerSec float64
	if stats.TotalBytesOut > 0 {
		byteRatio = float64(stats.TotalBytesIn) / float64(stats.TotalBytesOut)
	}
	if stats.TotalPacketsOut > 0 {
		packetRatio = float64(stats.TotalPacketsIn) / float64(stats.TotalPacketsOut)
	}
	if stats.TotalPacketsIn > 0 {
		avgPacketSize = float64(stats.TotalBytesIn) / float64(stats.TotalPacketsIn)
	}
	if stats.TotalDurationMs > 0 {
		packetsPerSec = float64(stats.TotalPacketsIn) / (float64(stats.TotalDurationMs) / 1000)
	}

	// Byte asymmetry (large response vs small request)
	if byteRatio > 5 {
		conf += 0.10
	}
	if byteRatio > 20 {
		conf += 0.05
	}

	// Packet ratio (many response packets per request)
	if packetRatio > 5 {
		conf += 0.10
	}
	if packetRatio > 20 {
		conf += 0.05
	}

	// Small average packet size (token streaming)
	if avgPacketSize > 0 && avgPacketSize < 500 {
		conf += 0.10
	}
	if avgPacketSize > 0 && avgPacketSize < 200 {
		conf += 0.05
	}

	// Sustained packet rate (continuous streaming)
	if packetsPerSec > 2 {
		conf += 0.10
	}

	// Long-lived connection
	if stats.TotalDurationMs > 5000 {
		conf += 0.10
	}

	// Source combination scoring
	hasTLS := stats.Sources["tls"] > 0
	hasStreaming := stats.Sources["streaming"] > 0
	if hasTLS && hasStreaming {
		conf += 0.15 // Definitive connection + AI behavior
	} else if hasTLS {
		conf += 0.05 // Saw handshake, no streaming yet
	} else if hasStreaming {
		conf += 0.05 // Detected pattern, missed handshake
	}

	// Concurrent connections to same destination
	if stats.MaxConcurrent > 1 {
		conf += 0.05
	}

	// Programmatic TLS client
	if stats.IsProgrammatic {
		conf += 0.10
	}

	// Observation frequency
	if stats.Count >= 3 {
		conf += 0.05
	}
	if stats.Count >= 10 {
		conf += 0.05
	}

	// Infrastructure penalty (applied after all boosts)
	conf -= infrastructurePenalty(stats.Domain)
	if conf < 0 {
		conf = 0
	}

	if conf > 0.99 {
		conf = 0.99
	}

	return conf
}

func (a *MemoryAccumulator) Count(process, domain string) int {
	key := process + ":" + normalizeDomain(domain)

	a.mu.RLock()
	defer a.mu.RUnlock()

	if stats, ok := a.pairs[key]; ok {
		return stats.Count
	}
	return 0
}

func (a *MemoryAccumulator) Stats(process, domain string) *PairStats {
	key := process + ":" + normalizeDomain(domain)

	a.mu.RLock()
	defer a.mu.RUnlock()

	if stats, ok := a.pairs[key]; ok {
		cp := *stats
		cp.Sources = make(map[string]int)
		for k, v := range stats.Sources {
			cp.Sources[k] = v
		}
		return &cp
	}
	return nil
}

func (a *MemoryAccumulator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pairs = make(map[string]*PairStats)
}
