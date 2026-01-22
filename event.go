package sai

import (
	"fmt"
	"time"
)

type Confidence float64

func (c Confidence) String() string {
	return fmt.Sprintf("%.2f", c)
}

// Event represents a process calling a domain
type Event struct {
	Timestamp  time.Time         `json:"ts"`
	PID        int               `json:"pid"`
	Process    string            `json:"proc"`
	BinaryPath string            `json:"binary"`
	Domain     string            `json:"domain"`
	Source     string            `json:"source"` // tls, dns, streaming
	JA4        string            `json:"ja4,omitempty"`
	Agent      string            `json:"agent,omitempty"` // matched agent name
	Confidence Confidence        `json:"confidence,omitempty"`
	Extras     map[string]string `json:"extras,omitempty"`
}

// ConnectionKey identifies a unique connection (4-tuple)
type ConnectionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// TrafficFeatures extracted from connection stats
type TrafficFeatures struct {
	StartTime       time.Time
	Duration        time.Duration
	PacketsIn       int
	PacketsOut      int
	BytesIn         int64
	BytesOut        int64
	ByteRatio       float64
	IsLongLived     bool
	IsStreaming     bool
	IsAsymmetric    bool
	ConcurrentConns int
	IsNewConn       bool
	DNSFresh        bool
	PID             int
	DstIP           string
}

// Agent represents a process that uses AI
type Agent struct {
	ID             int64    `json:"id,omitempty"`
	Name           string   `json:"name"`
	ProcessPattern string   `json:"process"`
	Domains        []string `json:"domains,omitempty"`
}

type IgnoreRule struct {
	ID  int64  `json:"id,omitempty"`
	URL string `json:"url"`
}
