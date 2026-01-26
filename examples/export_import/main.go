// Export/Import example.
// Shows how to use FilterSet with custom storage instead of file-based persistence.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/knostic/sai"
)

func main() {
	fs := sai.NewFilterSet()
	fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
	fs.AddAgent("openai", "python*", []string{"*.openai.com", "api.openai.com"})
	fs.AddNonAIDomain("google.com")
	fs.AddNonAIDomain("apple.com")

	data := fs.Export()

	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println("Exported data:")
	fmt.Println(string(jsonBytes))

	// Simulate storing and retrieving from external storage
	// In practice: saveToRedis(jsonBytes), loadFromPostgres(), etc.

	loaded := sai.NewFilterSet()
	loaded.Import(data)

	fmt.Println("\nVerifying imported data:")

	tests := []struct {
		process string
		domain  string
	}{
		{"claude-code", "api.anthropic.com"},
		{"python3", "api.openai.com"},
		{"chrome", "google.com"},
		{"safari", "icloud.apple.com"},
		{"curl", "api.mystery.com"},
	}

	for _, t := range tests {
		agent := loaded.MatchAgent(t.process, t.domain)
		nonAI := loaded.IsNonAIDomain(t.domain)

		status := "unknown"
		if agent != "" {
			status = fmt.Sprintf("agent:%s", agent)
		} else if nonAI {
			status = "non-AI"
		}

		fmt.Printf("  %s -> %s : %s\n", t.process, t.domain, status)
	}
}
