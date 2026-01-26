// Export/Import example.
// Shows how to use Overrides with custom storage instead of file-based persistence.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/knostic/sai"
)

func main() {
	fs := sai.NewOverrides()
	fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
	fs.AddAgent("openai", "python*", []string{"*.openai.com", "api.openai.com"})
	fs.AddNoise("google.com")
	fs.AddNoise("apple.com")

	data := fs.Export()

	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println("Exported data:")
	fmt.Println(string(jsonBytes))

	// Simulate storing and retrieving from external storage
	// In practice: saveToRedis(jsonBytes), loadFromPostgres(), etc.
	//
	// For Sigma YAML format (SIEM integration):
	//   yamlData, _ := sai.OverridesToSigmaYAML(data)
	//   parsed, _ := sai.SigmaYAMLToOverrides(yamlData)

	loaded := sai.NewOverrides()
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
		nonAI := loaded.IsNoise(t.domain)

		status := "unknown"
		if agent != "" {
			status = fmt.Sprintf("agent:%s", agent)
		} else if nonAI {
			status = "non-AI"
		}

		fmt.Printf("  %s -> %s : %s\n", t.process, t.domain, status)
	}
}
