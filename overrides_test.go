package sai

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAgentPatternMatching(t *testing.T) {
	tests := []struct {
		name        string
		procPattern string
		domainPat   string
		process     string
		domain      string
		shouldMatch bool
	}{
		{"wildcard_any", "*", "*.openai.com", "anyprocess", "api.openai.com", true},
		{"suffix_domain_match", "*", "*.openai.com", "curl", "api.openai.com", true},
		{"suffix_domain_exact", "*", "*.openai.com", "curl", "openai.com", true},
		{"suffix_domain_no_match", "*", "*.openai.com", "curl", "api.closed.com", false},
		{"prefix_process_match", "claude*", "*", "claude-code", "api.anthropic.com", true},
		{"prefix_process_no_match", "claude*", "*", "cursor", "api.anthropic.com", false},
		{"exact_match", "curl", "api.openai.com", "curl", "api.openai.com", true},
		{"exact_process_no_match", "curl", "api.openai.com", "wget", "api.openai.com", false},
		{"exact_domain_no_match", "curl", "api.openai.com", "curl", "api.anthropic.com", false},
		{"substring_process", "python", "*", "python3.10", "api.openai.com", true},
		{"substring_domain", "*", "openai", "curl", "api.openai.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewOverrides()
			o.AddAgent("test-agent", tt.procPattern, []string{tt.domainPat})

			got := o.MatchAgent(tt.process, tt.domain)
			if tt.shouldMatch && got == "" {
				t.Errorf("expected match for process=%q domain=%q (proc_pat=%q, dom_pat=%q)",
					tt.process, tt.domain, tt.procPattern, tt.domainPat)
			}
			if !tt.shouldMatch && got != "" {
				t.Errorf("expected no match for process=%q domain=%q, got %q", tt.process, tt.domain, got)
			}
		})
	}
}

func TestAgentMatchRequiresBothProcessAndDomain(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("openai", "python*", []string{"*.openai.com"})

	if o.MatchAgent("python3", "api.openai.com") == "" {
		t.Error("should match when both process and domain match")
	}

	if o.MatchAgent("python3", "api.anthropic.com") != "" {
		t.Error("should not match when domain doesn't match")
	}

	if o.MatchAgent("curl", "api.openai.com") != "" {
		t.Error("should not match when process doesn't match")
	}
}

func TestMatchIsCaseInsensitive(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("test", "Python*", []string{"*.OpenAI.com"})

	if o.MatchAgent("PYTHON3", "API.OPENAI.COM") == "" {
		t.Error("match should be case insensitive")
	}
	if o.MatchAgent("python3", "api.openai.com") == "" {
		t.Error("match should work with lowercase")
	}
}

func TestNoiseBlocksSubdomains(t *testing.T) {
	o := NewOverrides()
	o.AddNoise("google.com")

	tests := []struct {
		domain      string
		shouldBlock bool
	}{
		{"google.com", true},
		{"api.google.com", true},
		{"www.google.com", true},
		{"deep.nested.google.com", true},
		{"notgoogle.com", false},
		{"google.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := o.IsNoise(tt.domain)
			if got != tt.shouldBlock {
				t.Errorf("IsNoise(%q) = %v, want %v", tt.domain, got, tt.shouldBlock)
			}
		})
	}
}

func TestOverridesSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.bin")

	o := NewOverrides()
	o.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
	o.AddAgent("openai", "python*", []string{"*.openai.com", "api.openai.com"})
	o.AddNoise("google.com")
	o.AddNoise("apple.com")

	if err := o.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded := NewOverrides()
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.MatchAgent("claude-code", "api.anthropic.com") == "" {
		t.Error("loaded Overrides should match claude agent")
	}
	if loaded.MatchAgent("python3", "api.openai.com") == "" {
		t.Error("loaded Overrides should match openai agent")
	}
	if !loaded.IsNoise("google.com") {
		t.Error("loaded Overrides should have google.com as noise")
	}
	if !loaded.IsNoise("api.apple.com") {
		t.Error("loaded Overrides should block apple.com subdomains")
	}
}

func TestDomainNormalization(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("test", "*", []string{"example.com"})

	tests := []struct {
		domain      string
		shouldMatch bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true},
		{"www.example.com", true},
		{"WWW.EXAMPLE.COM", true},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := o.MatchAgent("test", tt.domain)
			if tt.shouldMatch && got == "" {
				t.Errorf("expected match for %q", tt.domain)
			}
		})
	}
}

func TestMatchAgentPriority(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("first", "*", []string{"*.example.com"})
	o.AddAgent("second", "*", []string{"*.example.com"})

	got := o.MatchAgent("test", "api.example.com")
	if got != "first" {
		t.Errorf("first matching agent should win, got %q", got)
	}
}

func TestEmptyOverrides(t *testing.T) {
	o := NewOverrides()

	if o.MatchAgent("curl", "api.openai.com") != "" {
		t.Error("empty Overrides should not match any agent")
	}

	if o.IsNoise("google.com") {
		t.Error("empty Overrides should not have any noise domains")
	}
}

func TestAddAgentDomain(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("test", "curl", []string{"api.example.com"})
	o.AddAgentDomain("test", "api.other.com")

	if o.MatchAgent("curl", "api.example.com") == "" {
		t.Error("should match original domain")
	}
	if o.MatchAgent("curl", "api.other.com") == "" {
		t.Error("should match added domain")
	}
}

func TestAddAgentDomainNonExistent(t *testing.T) {
	o := NewOverrides()
	o.AddAgentDomain("nonexistent", "api.example.com")

	agents := o.ListAgents()
	if len(agents) != 0 {
		t.Error("adding domain to non-existent agent should not create agent")
	}
}

func TestRemoveAgent(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("test", "curl", []string{"api.example.com"})

	if o.MatchAgent("curl", "api.example.com") == "" {
		t.Error("agent should match before removal")
	}

	o.RemoveAgent("test")

	if o.MatchAgent("curl", "api.example.com") != "" {
		t.Error("agent should not match after removal")
	}
}

func TestRemoveNoise(t *testing.T) {
	o := NewOverrides()
	o.AddNoise("google.com")

	if !o.IsNoise("google.com") {
		t.Error("domain should be noise")
	}

	o.RemoveNoise("google.com")

	if o.IsNoise("google.com") {
		t.Error("google.com should not be noise after removal")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
	o.AddAgent("openai", "python*", []string{"*.openai.com", "api.openai.com"})
	o.AddNoise("google.com")
	o.AddNoise("apple.com")

	data := o.Export()

	if len(data.Agents) != 2 {
		t.Errorf("exported agents = %d, want 2", len(data.Agents))
	}
	if len(data.Noise) != 2 {
		t.Errorf("exported noise = %d, want 2", len(data.Noise))
	}

	loaded := NewOverrides()
	loaded.Import(data)

	if loaded.MatchAgent("claude-code", "api.anthropic.com") == "" {
		t.Error("imported Overrides should match claude agent")
	}
	if loaded.MatchAgent("python3", "api.openai.com") == "" {
		t.Error("imported Overrides should match openai agent")
	}
	if !loaded.IsNoise("google.com") {
		t.Error("imported Overrides should have google.com as noise")
	}
	if !loaded.IsNoise("api.apple.com") {
		t.Error("imported Overrides should block apple.com subdomains")
	}
}

func TestExportImportIsolated(t *testing.T) {
	o := NewOverrides()
	o.AddAgent("test", "test*", []string{"*.test.com"})
	o.AddNoise("example.com")

	data := o.Export()

	data.Agents[0].Name = "modified"
	data.Noise[0] = "modified.com"

	if o.MatchAgent("test-app", "api.test.com") != "test" {
		t.Error("modifying exported data should not affect original")
	}
	if !o.IsNoise("example.com") {
		t.Error("modifying exported data should not affect original noise")
	}
}

func TestAddAgentSetsMetadata(t *testing.T) {
	before := time.Now()
	o := NewOverrides()
	o.AddAgent("test", "test*", []string{"*.test.com"})
	after := time.Now()

	agent := o.GetAgent("test")
	if agent == nil {
		t.Fatal("agent not found")
	}
	if agent.CreatedAt.Before(before) || agent.CreatedAt.After(after) {
		t.Errorf("CreatedAt should be between %v and %v, got %v", before, after, agent.CreatedAt)
	}
}

func TestMetadataSurvivesSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.bin")

	o := NewOverrides()
	o.AddAgent("test", "test*", []string{"*.test.com"})

	original := o.GetAgent("test")
	if original == nil {
		t.Fatal("agent not found")
	}

	if err := o.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded := NewOverrides()
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	agent := loaded.GetAgent("test")
	if agent == nil {
		t.Fatal("loaded agent not found")
	}
	if !agent.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt not preserved: got %v, want %v", agent.CreatedAt, original.CreatedAt)
	}
}

func TestImportPreservesMetadata(t *testing.T) {
	createdAt := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	data := OverridesData{
		Agents: []Agent{
			{Name: "test", Process: "test*", Domains: []string{"*.test.com"}, CreatedAt: createdAt},
		},
	}

	o := NewOverrides()
	o.Import(data)

	agent := o.GetAgent("test")
	if agent == nil {
		t.Fatal("imported agent not found")
	}
	if !agent.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt = %v, want %v", agent.CreatedAt, createdAt)
	}
}

func TestBackwardCompatibilityZeroMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.bin")

	data := OverridesData{
		Agents: []Agent{
			{Name: "legacy", Process: "legacy*", Domains: []string{"*.legacy.com"}},
		},
	}

	o := NewOverrides()
	o.Import(data)
	if err := o.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded := NewOverrides()
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	agent := loaded.GetAgent("legacy")
	if agent == nil {
		t.Fatal("legacy agent not found")
	}
	if !agent.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be zero for legacy data, got %v", agent.CreatedAt)
	}
}
