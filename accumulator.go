package sai

import (
	"maps"
	"strconv"
	"sync"
	"time"
)

type Accumulator interface {
	Record(event Event)
	Confidence(process, domain string) Confidence
	Count(process, domain string) int
	Stats(process, domain string) *PairStats
}

type PairStats struct {
	Process         string
	Domain          string
	Count           int
	FirstSeen       time.Time
	LastSeen        time.Time
	Sources         map[string]int
	IsProgrammatic  bool
	TotalBytesIn    int64
	TotalBytesOut   int64
	TotalPacketsIn  int
	TotalPacketsOut int
	TotalDurationMs int64
	MaxConcurrent   int
	BaseConfidence  Confidence
}

type MemoryAccumulator struct {
	signals  Signals
	registry *ClassifierRegistry
	pairs    map[string]*PairStats
	mu       sync.RWMutex
}

func NewAccumulator() *MemoryAccumulator {
	return NewAccumulatorWithSignals(NewFilterSet(), NewClassifierRegistry())
}

func NewAccumulatorWithSignals(signals Signals, registry *ClassifierRegistry) *MemoryAccumulator {
	return &MemoryAccumulator{
		signals:  signals,
		registry: registry,
		pairs:    make(map[string]*PairStats),
	}
}

func NewAccumulatorWithFilters(filterSet *FilterSet, registry *ClassifierRegistry) *MemoryAccumulator {
	return NewAccumulatorWithSignals(filterSet, registry)
}

func (a *MemoryAccumulator) Signals() Signals {
	return a.signals
}

func (a *MemoryAccumulator) Registry() *ClassifierRegistry {
	return a.registry
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
		stats.BaseConfidence = a.classifyDomain(event.Process, event.Domain)
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

func (a *MemoryAccumulator) classifyDomain(process, domain string) Confidence {
	if a.signals == nil {
		return 0.0
	}

	if a.signals.MatchAgent(process, domain) != "" {
		return 1.0
	}

	if a.signals.IsNonAI(process, domain) || a.signals.IsNonAIDomain(domain) {
		return 0.0
	}

	return 0.0
}

func (a *MemoryAccumulator) Confidence(process, domain string) Confidence {
	key := process + ":" + normalizeDomain(domain)

	a.mu.RLock()
	defer a.mu.RUnlock()

	stats, ok := a.pairs[key]
	if !ok {
		base := a.classifyDomain(process, domain)
		if base > 0 {
			return base
		}
		if a.registry != nil {
			return a.registry.Classify(ClassifierInput{
				Domain:  domain,
				Process: process,
			})
		}
		return 0
	}

	if stats.BaseConfidence >= 1.0 {
		return 1.0
	}
	if stats.BaseConfidence == 0.0 && a.signals != nil {
		if a.signals.IsNonAI(process, domain) || a.signals.IsNonAIDomain(domain) {
			return 0.0
		}
	}

	conf := stats.BaseConfidence
	if a.registry != nil {
		input := ClassifierInput{
			Domain:  domain,
			Process: process,
			Stats:   stats,
		}
		heuristic := a.registry.Classify(input)
		if heuristic > conf {
			conf = heuristic
		}
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
		maps.Copy(cp.Sources, stats.Sources)
		return &cp
	}
	return nil
}

func (a *MemoryAccumulator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pairs = make(map[string]*PairStats)
}
