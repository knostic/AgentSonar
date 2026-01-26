package sai

import "strings"

type DefaultClassifier struct{}

func NewDefaultClassifier() *DefaultClassifier {
	return &DefaultClassifier{}
}

func (d *DefaultClassifier) Name() string {
	return "default"
}

func (d *DefaultClassifier) Classify(input ClassifierInput) (AIScore, error) {
	var score AIScore

	if input.Stats == nil {
		return score - infrastructurePenalty(input.Domain), nil
	}

	stats := input.Stats

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

	if byteRatio > 5 {
		score += 0.10
	}
	if byteRatio > 20 {
		score += 0.05
	}

	if packetRatio > 5 {
		score += 0.10
	}
	if packetRatio > 20 {
		score += 0.05
	}

	if avgPacketSize > 0 && avgPacketSize < 500 {
		score += 0.10
	}
	if avgPacketSize > 0 && avgPacketSize < 200 {
		score += 0.05
	}

	if packetsPerSec > 2 {
		score += 0.10
	}

	if stats.TotalDurationMs > 5000 {
		score += 0.10
	}

	hasTLS := stats.Sources["tls"] > 0
	hasStreaming := stats.Sources["streaming"] > 0
	if hasTLS && hasStreaming {
		score += 0.15
	} else if hasTLS {
		score += 0.05
	} else if hasStreaming {
		score += 0.05
	}

	if stats.MaxConcurrent > 1 {
		score += 0.05
	}

	if stats.IsProgrammatic {
		score += 0.10
	}

	if stats.Count >= 3 {
		score += 0.05
	}
	if stats.Count >= 10 {
		score += 0.05
	}

	score -= infrastructurePenalty(input.Domain)
	if score < 0 {
		score = 0
	}

	return score, nil
}

func (d *DefaultClassifier) Close() error {
	return nil
}

var infrastructurePenalties = map[string]AIScore{
	"logs":           0.5,
	"log":            0.5,
	"logging":        0.5,
	"telemetry":      0.5,
	"metrics":        0.4,
	"intake":         0.4,
	"analytics":      0.4,
	"tracking":       0.4,
	"tracker":        0.4,
	"statsig":        0.4,
	"events":         0.3,
	"cdn":            0.3,
	"static":         0.3,
	"assets":         0.3,
	"media":          0.3,
	"gateway":        0.3,
	"cloudkit":       0.4,
	"apple-cloudkit": 0.4,
	"cloudfront":     0.4,
	"cloudflare":     0.4,
	"akamai":         0.4,
	"fastly":         0.4,
	"icloud":         0.4,
	"stats":          0.3,
	"status":         0.3,
	"health":         0.3,
	"auth":           0.2,
	"oauth":          0.2,
	"oauth2":         0.2,
	"login":          0.2,
	"sso":            0.2,
	"ocsp":           0.5,
	"ocsp2":          0.5,
	"crl":            0.5,
}

func infrastructurePenalty(domain string) AIScore {
	var totalPenalty AIScore
	parts := strings.SplitSeq(domain, ".")
	for part := range parts {
		if penalty, ok := infrastructurePenalties[part]; ok {
			totalPenalty += penalty
		}
	}
	return totalPenalty
}
