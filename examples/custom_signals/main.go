// Custom Signals implementation example.
// Shows how to implement the Signals interface for your own storage backend.
package main

import (
	"fmt"
	"strings"

	"github.com/knostic/sai"
)

// MapSignals is a simple in-memory Signals implementation.
// Replace with your own database-backed implementation.
type MapSignals struct {
	agents      map[string][]string // agent name -> domain patterns
	processes   map[string]string   // process pattern -> agent name
	nonAIDomains map[string]bool
}

func NewMapSignals() *MapSignals {
	return &MapSignals{
		agents:       make(map[string][]string),
		processes:    make(map[string]string),
		nonAIDomains: make(map[string]bool),
	}
}

func (s *MapSignals) AddAgent(name, processPattern string, domains []string) {
	s.agents[name] = domains
	s.processes[processPattern] = name
}

func (s *MapSignals) AddNoise(domain string) {
	s.nonAIDomains[strings.ToLower(domain)] = true
}

func (s *MapSignals) MatchAgent(process, domain string) string {
	process = strings.ToLower(process)
	domain = strings.ToLower(domain)

	for pattern, agentName := range s.processes {
		if !matchPattern(process, pattern) {
			continue
		}
		for _, domainPattern := range s.agents[agentName] {
			if matchPattern(domain, domainPattern) {
				return agentName
			}
		}
	}
	return ""
}

func (s *MapSignals) IsNonAI(process, domain string) bool {
	return s.IsNonAIDomain(domain)
}

func (s *MapSignals) IsNonAIDomain(domain string) bool {
	domain = strings.ToLower(domain)
	if s.nonAIDomains[domain] {
		return true
	}
	for d := range s.nonAIDomains {
		if strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func matchPattern(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(s, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return s == pattern || strings.Contains(s, pattern)
}

func main() {
	signals := NewMapSignals()
	signals.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
	signals.AddAgent("openai", "python*", []string{"*.openai.com"})
	signals.AddNoise("google.com")

	registry := sai.NewClassifierRegistry()
	registry.Add(sai.NewDefaultClassifier())

	acc := sai.NewAccumulatorWithSignals(signals, registry)

	events := []sai.Event{
		{Process: "claude-code", Domain: "api.anthropic.com", Source: "tls"},
		{Process: "python3", Domain: "api.openai.com", Source: "tls"},
		{Process: "chrome", Domain: "www.google.com", Source: "tls"},
		{Process: "unknown-app", Domain: "api.mystery.com", Source: "tls"},
	}

	for _, event := range events {
		acc.Record(event)
		agent := signals.MatchAgent(event.Process, event.Domain)
		conf := acc.Confidence(event.Process, event.Domain)

		status := "unknown"
		if agent != "" {
			status = fmt.Sprintf("agent:%s", agent)
		} else if signals.IsNonAIDomain(event.Domain) {
			status = "non-AI"
		}

		fmt.Printf("%s -> %s [%s] conf=%.2f\n",
			event.Process, event.Domain, status, conf)
	}
}
