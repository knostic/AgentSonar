package sai

import (
	"testing"
)

func TestByteRatioScoring(t *testing.T) {
	classifier := NewDefaultClassifier()

	baseStats := makeStatsInput(5000, 5000, 10, 10, 100, nil)
	baseInput := ClassifierInput{Domain: "example.com", Stats: baseStats}
	baseConf, _ := classifier.Classify(baseInput)

	highRatioStats := makeStatsInput(30000, 5000, 10, 10, 100, nil)
	highRatioInput := ClassifierInput{Domain: "example.com", Stats: highRatioStats}
	highRatioConf, _ := classifier.Classify(highRatioInput)

	if highRatioConf <= baseConf {
		t.Errorf("high byte ratio (%v) should score higher than base (%v)", highRatioConf, baseConf)
	}

	veryHighRatioStats := makeStatsInput(105000, 5000, 10, 10, 100, nil)
	veryHighRatioInput := ClassifierInput{Domain: "example.com", Stats: veryHighRatioStats}
	veryHighRatioConf, _ := classifier.Classify(veryHighRatioInput)

	if veryHighRatioConf <= highRatioConf {
		t.Errorf("very high byte ratio (%v) should score higher than high (%v)", veryHighRatioConf, highRatioConf)
	}
}

func TestPacketRatioScoring(t *testing.T) {
	classifier := NewDefaultClassifier()

	tests := []struct {
		name        string
		packetsIn   int
		packetsOut  int
		wantMinConf AIScore
	}{
		{
			name:        "ratio_below_5",
			packetsIn:   400,
			packetsOut:  100,
			wantMinConf: 0.0,
		},
		{
			name:        "ratio_above_5",
			packetsIn:   600,
			packetsOut:  100,
			wantMinConf: 0.10,
		},
		{
			name:        "ratio_above_20",
			packetsIn:   2100,
			packetsOut:  100,
			wantMinConf: 0.15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := makeStatsInput(10000, 10000, tt.packetsIn, tt.packetsOut, 1000, nil)
			input := ClassifierInput{Domain: "example.com", Stats: stats}
			conf, err := classifier.Classify(input)
			if err != nil {
				t.Fatalf("classify error: %v", err)
			}
			if conf < tt.wantMinConf {
				t.Errorf("got confidence %v, want at least %v", conf, tt.wantMinConf)
			}
		})
	}
}

func TestSmallPacketScoring(t *testing.T) {
	classifier := NewDefaultClassifier()

	tests := []struct {
		name        string
		bytesIn     int64
		packetsIn   int
		wantMinConf AIScore
		description string
	}{
		{
			name:        "large_packets",
			bytesIn:     100000,
			packetsIn:   100,
			wantMinConf: 0.0,
			description: "avg 1000 bytes should not add score",
		},
		{
			name:        "medium_packets",
			bytesIn:     30000,
			packetsIn:   100,
			wantMinConf: 0.10,
			description: "avg 300 bytes (<500) should add 0.10",
		},
		{
			name:        "small_packets",
			bytesIn:     15000,
			packetsIn:   100,
			wantMinConf: 0.15,
			description: "avg 150 bytes (<200) should add 0.15 total",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := makeStatsInput(tt.bytesIn, 10000, tt.packetsIn, 100, 1000, nil)
			input := ClassifierInput{Domain: "example.com", Stats: stats}
			conf, err := classifier.Classify(input)
			if err != nil {
				t.Fatalf("classify error: %v", err)
			}
			if conf < tt.wantMinConf {
				t.Errorf("got confidence %v, want at least %v (%s)", conf, tt.wantMinConf, tt.description)
			}
		})
	}
}

func TestHighPacketRateScoring(t *testing.T) {
	classifier := NewDefaultClassifier()

	lowRate := makeStatsInput(10000, 10000, 100, 100, 100000, nil)
	input := ClassifierInput{Domain: "example.com", Stats: lowRate}
	confLow, _ := classifier.Classify(input)

	highRate := makeStatsInput(10000, 10000, 500, 100, 100000, nil)
	input = ClassifierInput{Domain: "example.com", Stats: highRate}
	confHigh, _ := classifier.Classify(input)

	if confHigh <= confLow {
		t.Errorf("high packet rate (%v) should score higher than low rate (%v)", confHigh, confLow)
	}
}

func TestLongDurationScoring(t *testing.T) {
	classifier := NewDefaultClassifier()

	shortDuration := makeStatsInput(10000, 10000, 100, 100, 1000, nil)
	input := ClassifierInput{Domain: "example.com", Stats: shortDuration}
	confShort, _ := classifier.Classify(input)

	longDuration := makeStatsInput(10000, 10000, 100, 100, 10000, nil)
	input = ClassifierInput{Domain: "example.com", Stats: longDuration}
	confLong, _ := classifier.Classify(input)

	if confLong < confShort+0.10 {
		t.Errorf("long duration (%v) should add 0.10 vs short (%v)", confLong, confShort)
	}
}

func TestSourceCombinations(t *testing.T) {
	classifier := NewDefaultClassifier()

	tlsOnly := makeStatsInput(1000, 1000, 10, 10, 1000, map[string]int{"tls": 1})
	input := ClassifierInput{Domain: "example.com", Stats: tlsOnly}
	confTLS, _ := classifier.Classify(input)

	streamingOnly := makeStatsInput(1000, 1000, 10, 10, 1000, map[string]int{"streaming": 1})
	input = ClassifierInput{Domain: "example.com", Stats: streamingOnly}
	confStreaming, _ := classifier.Classify(input)

	both := makeStatsInput(1000, 1000, 10, 10, 1000, map[string]int{"tls": 1, "streaming": 1})
	input = ClassifierInput{Domain: "example.com", Stats: both}
	confBoth, _ := classifier.Classify(input)

	none := makeStatsInput(1000, 1000, 10, 10, 1000, map[string]int{"dns": 1})
	input = ClassifierInput{Domain: "example.com", Stats: none}
	confNone, _ := classifier.Classify(input)

	if confBoth < confTLS || confBoth < confStreaming {
		t.Errorf("both sources (%v) should score >= individual (tls=%v, streaming=%v)", confBoth, confTLS, confStreaming)
	}
	if confTLS <= confNone || confStreaming <= confNone {
		t.Errorf("tls (%v) or streaming (%v) should score higher than neither (%v)", confTLS, confStreaming, confNone)
	}
}

func TestCountThresholds(t *testing.T) {
	classifier := NewDefaultClassifier()

	tests := []struct {
		name        string
		count       int
		wantMinConf AIScore
	}{
		{"count_1", 1, 0.0},
		{"count_3", 3, 0.05},
		{"count_10", 10, 0.10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := makeStatsInput(1000, 1000, 10, 10, 1000, nil)
			stats.Count = tt.count
			input := ClassifierInput{Domain: "example.com", Stats: stats}
			conf, _ := classifier.Classify(input)
			if conf < tt.wantMinConf {
				t.Errorf("count %d: got confidence %v, want at least %v", tt.count, conf, tt.wantMinConf)
			}
		})
	}
}

func TestInfrastructurePenalty(t *testing.T) {
	classifier := NewDefaultClassifier()
	stats := makeStatsInput(10000, 1000, 100, 10, 10000, map[string]int{"tls": 1, "streaming": 1})
	stats.Count = 10

	normalInput := ClassifierInput{Domain: "api.example.com", Stats: stats}
	confNormal, _ := classifier.Classify(normalInput)

	penaltyDomains := []string{
		"logs.example.com",
		"cdn.example.com",
		"ocsp.example.com",
		"telemetry.example.com",
	}

	for _, domain := range penaltyDomains {
		input := ClassifierInput{Domain: domain, Stats: stats}
		conf, _ := classifier.Classify(input)
		if conf >= confNormal {
			t.Errorf("domain %s (%v) should have lower confidence than normal (%v)", domain, conf, confNormal)
		}
	}
}

func TestNilStatsOnlyAppliesPenalty(t *testing.T) {
	classifier := NewDefaultClassifier()

	normalInput := ClassifierInput{Domain: "api.example.com", Stats: nil}
	confNormal, _ := classifier.Classify(normalInput)

	logsInput := ClassifierInput{Domain: "logs.example.com", Stats: nil}
	confLogs, _ := classifier.Classify(logsInput)

	if confNormal != 0 {
		t.Errorf("nil stats with normal domain should be 0, got %v", confNormal)
	}
	if confLogs > confNormal {
		t.Errorf("penalty domain (%v) should not score higher than normal (%v)", confLogs, confNormal)
	}
}

func TestRegistryReturnsAverageAIScore(t *testing.T) {
	registry := NewClassifierRegistry()

	registry.Add(&mockClassifier{name: "low", conf: 0.3})
	registry.Add(&mockClassifier{name: "high", conf: 0.9})
	registry.Add(&mockClassifier{name: "mid", conf: 0.6})

	input := ClassifierInput{Domain: "example.com"}
	score := registry.Classify(input)

	expected := AIScore(0.6) // (0.3 + 0.9 + 0.6) / 3 = 0.6
	if score != expected {
		t.Errorf("registry should return average 0.6, got %v", score)
	}
}

func TestEmptyRegistryReturnsZero(t *testing.T) {
	registry := NewClassifierRegistry()

	input := ClassifierInput{Domain: "example.com"}
	conf := registry.Classify(input)

	if conf != 0 {
		t.Errorf("empty registry should return 0, got %v", conf)
	}
}

type mockClassifier struct {
	name string
	conf AIScore
}

func (m *mockClassifier) Name() string                                   { return m.name }
func (m *mockClassifier) Classify(input ClassifierInput) (AIScore, error) { return m.conf, nil }
func (m *mockClassifier) Close() error                                   { return nil }
