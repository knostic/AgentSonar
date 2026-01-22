//go:build darwin

package capture

import (
	"sync"
	"time"

	"github.com/knostic/sai/types"
)

type connectionStats struct {
	Key         types.ConnectionKey
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount int
	BytesOut    int64
	BytesIn     int64
	PacketsOut  int
	PacketsIn   int
}

type trafficAnalyzer struct {
	connections map[types.ConnectionKey]*connectionStats
	mu          sync.RWMutex
	maxConns    int
}

func newTrafficAnalyzer() *trafficAnalyzer {
	return &trafficAnalyzer{
		connections: make(map[types.ConnectionKey]*connectionStats),
		maxConns:    10000,
	}
}

func (t *trafficAnalyzer) TrackConnection(key types.ConnectionKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.connections[key]; exists {
		return
	}

	if len(t.connections) >= t.maxConns {
		t.evictOldest()
	}
	t.connections[key] = &connectionStats{
		Key:       key,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

func (t *trafficAnalyzer) UpdateFromNetstat(key types.ConnectionKey, bytesIn, bytesOut int64, packetsIn, packetsOut int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats, exists := t.connections[key]
	if !exists {
		return
	}

	stats.BytesIn = bytesIn
	stats.BytesOut = bytesOut
	stats.PacketsIn = packetsIn
	stats.PacketsOut = packetsOut
	stats.PacketCount = packetsIn + packetsOut
	stats.LastSeen = time.Now()
}

func (t *trafficAnalyzer) GetFeatures(key types.ConnectionKey) *types.TrafficFeatures {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats, exists := t.connections[key]
	if !exists {
		return nil
	}

	return extractFeatures(stats)
}

func (t *trafficAnalyzer) GetAllActive(since time.Duration) map[types.ConnectionKey]*types.TrafficFeatures {
	t.mu.RLock()
	defer t.mu.RUnlock()

	cutoff := time.Now().Add(-since)
	result := make(map[types.ConnectionKey]*types.TrafficFeatures)

	for key, stats := range t.connections {
		if stats.LastSeen.After(cutoff) {
			result[key] = extractFeatures(stats)
		}
	}

	return result
}

func extractFeatures(stats *connectionStats) *types.TrafficFeatures {
	f := &types.TrafficFeatures{
		StartTime:  stats.FirstSeen,
		Duration:   stats.LastSeen.Sub(stats.FirstSeen),
		PacketsIn:  stats.PacketsIn,
		PacketsOut: stats.PacketsOut,
		BytesIn:    stats.BytesIn,
		BytesOut:   stats.BytesOut,
	}

	if stats.BytesOut > 0 {
		f.ByteRatio = float64(stats.BytesIn) / float64(stats.BytesOut)
	}

	f.IsLongLived = f.Duration > 5*time.Second
	f.IsAsymmetric = f.ByteRatio > 10
	f.IsStreaming = detectStreaming(stats)

	return f
}

func detectStreaming(stats *connectionStats) bool {
	if stats.PacketsIn < 10 {
		return false
	}

	duration := stats.LastSeen.Sub(stats.FirstSeen)
	if duration < 2*time.Second {
		return false
	}

	avgPacketSize := float64(stats.BytesIn) / float64(stats.PacketsIn)
	packetsPerSecond := float64(stats.PacketsIn) / duration.Seconds()

	return avgPacketSize < 500 && packetsPerSecond > 2
}

func (t *trafficAnalyzer) GetLastActivity(key types.ConnectionKey) time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if stats, ok := t.connections[key]; ok {
		return stats.LastSeen
	}
	return time.Time{}
}

func (t *trafficAnalyzer) CountConnectionsToIP(dstIP string, activeSince time.Duration) int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	cutoff := time.Now().Add(-activeSince)
	count := 0
	for key, stats := range t.connections {
		if key.DstIP == dstIP && stats.LastSeen.After(cutoff) {
			count++
		}
	}
	return count
}

func (t *trafficAnalyzer) evictOldest() {
	var oldestKey types.ConnectionKey
	var oldestTime time.Time

	for key, stats := range t.connections {
		if oldestTime.IsZero() || stats.LastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = stats.LastSeen
		}
	}

	delete(t.connections, oldestKey)
}
