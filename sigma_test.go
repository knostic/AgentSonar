package sai

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestPatternToSigmaField(t *testing.T) {
	tests := []struct {
		pattern string
		wantKey string
		wantVal any
	}{
		{"cursor*", "ProcessName|startswith", "cursor"},
		{"*.anthropic.com", "ProcessName|endswith", ".anthropic.com"},
		{"*openai*", "ProcessName|contains", "openai"},
		{"exact", "ProcessName", "exact"},
		{"*", "ProcessName", nil},
		{"*suffix", "ProcessName|endswith", "suffix"},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			gotKey, gotVal := patternToSigmaField("ProcessName", tt.pattern)
			if gotKey != tt.wantKey {
				t.Errorf("patternToSigmaField(%q) key = %q, want %q", tt.pattern, gotKey, tt.wantKey)
			}
			if gotVal != tt.wantVal {
				t.Errorf("patternToSigmaField(%q) val = %v, want %v", tt.pattern, gotVal, tt.wantVal)
			}
		})
	}
}

func TestSigmaValueToPattern(t *testing.T) {
	tests := []struct {
		modifier string
		val      any
		want     string
	}{
		{"startswith", "cursor", "cursor*"},
		{"endswith", ".anthropic.com", "*.anthropic.com"},
		{"endswith", "suffix", "*suffix"},
		{"contains", "openai", "*openai*"},
		{"", "exact", "exact"},
	}

	for _, tt := range tests {
		t.Run(tt.modifier+"/"+tt.val.(string), func(t *testing.T) {
			got := sigmaValueToPattern(tt.modifier, tt.val)
			if got != tt.want {
				t.Errorf("sigmaValueToPattern(%q, %v) = %q, want %q", tt.modifier, tt.val, got, tt.want)
			}
		})
	}
}

func TestAgentToSigma(t *testing.T) {
	agent := Agent{
		Name:      "Cursor IDE",
		Process:   "cursor*",
		Domains:   []string{"*.anthropic.com", "*.openai.com"},
		CreatedAt: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
	}

	rule := AgentToSigma(agent)

	if rule.Title != "Cursor IDE" {
		t.Errorf("Title = %q, want %q", rule.Title, "Cursor IDE")
	}
	if rule.Status != "experimental" {
		t.Errorf("Status = %q, want %q", rule.Status, "experimental")
	}
	if rule.Author != "sai" {
		t.Errorf("Author = %q, want %q", rule.Author, "sai")
	}
	if rule.Date != "2025/01/15" {
		t.Errorf("Date = %q, want %q", rule.Date, "2025/01/15")
	}
	if rule.LogSource.Category != "network_connection" {
		t.Errorf("LogSource.Category = %q, want %q", rule.LogSource.Category, "network_connection")
	}
	if rule.Detection.Condition != "selection" {
		t.Errorf("Detection.Condition = %q, want %q", rule.Detection.Condition, "selection")
	}

	if rule.Detection.Selection["ProcessName|startswith"] != "cursor" {
		t.Errorf("ProcessName selection = %v, want %q", rule.Detection.Selection["ProcessName|startswith"], "cursor")
	}
}

func TestNoiseToSigmaFilter(t *testing.T) {
	domains := []string{"google.com", "facebook.com"}
	rule := NoiseToSigmaFilter(domains)

	if rule.Title != "sai Noise Filter" {
		t.Errorf("Title = %q, want %q", rule.Title, "sai Noise Filter")
	}
	if rule.Detection.Condition != "not filter" {
		t.Errorf("Condition = %q, want %q", rule.Detection.Condition, "not filter")
	}
	if rule.Detection.Filter == nil {
		t.Fatal("Filter is nil")
	}

	filterVal := rule.Detection.Filter["DestinationHostname|endswith"]
	vals, ok := filterVal.([]any)
	if !ok {
		t.Fatalf("Filter value is not []any: %T", filterVal)
	}
	if len(vals) != 2 {
		t.Errorf("Filter has %d values, want 2", len(vals))
	}
}

func TestSigmaToAgent(t *testing.T) {
	rule := SigmaRule{
		Title:  "Test Agent",
		Date:   "2025/01/15",
		Status: "experimental",
		Detection: SigmaDetection{
			Selection: map[string]any{
				"ProcessName|startswith":        "cursor",
				"DestinationHostname|endswith": ".anthropic.com",
			},
			Condition: "selection",
		},
	}

	agent, noise, err := SigmaToAgent(rule)
	if err != nil {
		t.Fatalf("SigmaToAgent() error = %v", err)
	}
	if len(noise) != 0 {
		t.Errorf("noise = %v, want empty", noise)
	}
	if agent.Name != "Test Agent" {
		t.Errorf("Name = %q, want %q", agent.Name, "Test Agent")
	}
	if agent.Process != "cursor*" {
		t.Errorf("Process = %q, want %q", agent.Process, "cursor*")
	}
	if len(agent.Domains) != 1 || agent.Domains[0] != "*.anthropic.com" {
		t.Errorf("Domains = %v, want [*.anthropic.com]", agent.Domains)
	}
}

func TestSigmaFilterToNoise(t *testing.T) {
	rule := SigmaRule{
		Title: "sai Noise Filter",
		Detection: SigmaDetection{
			Filter: map[string]any{
				"DestinationHostname|endswith": []any{"google.com", "facebook.com"},
			},
			Condition: "not filter",
		},
	}

	agent, noise, err := SigmaToAgent(rule)
	if err != nil {
		t.Fatalf("SigmaToAgent() error = %v", err)
	}
	if len(noise) != 2 {
		t.Errorf("noise = %v, want 2 domains", noise)
	}
	if agent.Name != "sai Noise Filter" {
		t.Errorf("Name = %q", agent.Name)
	}
}

func TestRoundtrip(t *testing.T) {
	original := OverridesData{
		Agents: []Agent{
			{
				Name:      "Claude Code",
				Process:   "claude*",
				Domains:   []string{"*.anthropic.com"},
				CreatedAt: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			},
			{
				Name:      "Cursor",
				Process:   "cursor*",
				Domains:   []string{"*.openai.com", "*.anthropic.com"},
				CreatedAt: time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC),
			},
		},
		Noise: []string{"google.com", "facebook.com"},
	}

	yamlData, err := OverridesToSigmaYAML(original)
	if err != nil {
		t.Fatalf("OverridesToSigmaYAML() error = %v", err)
	}

	parsed, err := SigmaYAMLToOverrides(yamlData)
	if err != nil {
		t.Fatalf("SigmaYAMLToOverrides() error = %v", err)
	}

	if len(parsed.Agents) != len(original.Agents) {
		t.Errorf("Agents count = %d, want %d", len(parsed.Agents), len(original.Agents))
	}

	for i, agent := range parsed.Agents {
		if agent.Name != original.Agents[i].Name {
			t.Errorf("Agent[%d].Name = %q, want %q", i, agent.Name, original.Agents[i].Name)
		}
		if agent.Process != original.Agents[i].Process {
			t.Errorf("Agent[%d].Process = %q, want %q", i, agent.Process, original.Agents[i].Process)
		}
	}

	if len(parsed.Noise) != len(original.Noise) {
		t.Errorf("Noise count = %d, want %d", len(parsed.Noise), len(original.Noise))
	}
}

func TestSigmaYAMLValidity(t *testing.T) {
	agent := Agent{
		Name:      "Test Agent",
		Process:   "test*",
		Domains:   []string{"*.example.com"},
		CreatedAt: time.Now().UTC(),
	}

	rule := AgentToSigma(agent)
	yamlData, err := yaml.Marshal(rule)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(yamlData, &parsed); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	required := []string{"title", "id", "status", "logsource", "detection", "level"}
	for _, field := range required {
		if _, ok := parsed[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	if len(rule.ID) != 36 {
		t.Errorf("ID length = %d, want 36 (UUID format)", len(rule.ID))
	}
	if !strings.Contains(rule.ID, "-") {
		t.Errorf("ID = %q, want UUID format with dashes", rule.ID)
	}
}

func TestSigmaCliValidation(t *testing.T) {
	if _, err := exec.LookPath("sigma"); err != nil {
		t.Skip("sigma-cli not installed")
	}

	data := OverridesData{
		Agents: []Agent{
			{
				Name:      "Test Agent",
				Process:   "test*",
				Domains:   []string{"*.example.com"},
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	yamlData, err := OverridesToSigmaYAML(data)
	if err != nil {
		t.Fatalf("OverridesToSigmaYAML() error = %v", err)
	}

	tmpFile := t.TempDir() + "/rules.yaml"
	if err := writeFile(tmpFile, yamlData); err != nil {
		t.Fatalf("writeFile() error = %v", err)
	}

	cmd := exec.Command("sigma", "check", tmpFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("sigma check failed: %v\nOutput: %s", err, output)
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
