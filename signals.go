package sai

// Signals provides known classifications for process:domain pairs.
// Implement this interface for custom storage backends.
type Signals interface {
	// MatchAgent returns the agent name if (process, domain) matches a known AI agent.
	// Returns empty string if no match.
	MatchAgent(process, domain string) string

	// IsNonAIDomain returns true if domain is known non-AI (ignores process).
	IsNonAIDomain(domain string) bool
}
