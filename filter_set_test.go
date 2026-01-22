//go:build darwin

package sai

import (
	"testing"
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
			fs := NewFilterSet()
			fs.AddAgent("test-agent", tt.procPattern, []string{tt.domainPat})

			got := fs.MatchAgent(tt.process, tt.domain)
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
	fs := NewFilterSet()
	fs.AddAgent("openai", "python*", []string{"*.openai.com"})

	if fs.MatchAgent("python3", "api.openai.com") == "" {
		t.Error("should match when both process and domain match")
	}

	if fs.MatchAgent("python3", "api.anthropic.com") != "" {
		t.Error("should not match when domain doesn't match")
	}

	if fs.MatchAgent("curl", "api.openai.com") != "" {
		t.Error("should not match when process doesn't match")
	}
}

func TestMatchIsCaseInsensitive(t *testing.T) {
	fs := NewFilterSet()
	fs.AddAgent("test", "Python*", []string{"*.OpenAI.com"})

	if fs.MatchAgent("PYTHON3", "API.OPENAI.COM") == "" {
		t.Error("match should be case insensitive")
	}
	if fs.MatchAgent("python3", "api.openai.com") == "" {
		t.Error("match should work with lowercase")
	}
}

func TestNonAIDomainBlocksSubdomains(t *testing.T) {
	fs := NewFilterSet()
	fs.AddNonAIDomain("google.com")

	tests := []struct {
		domain    string
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
			got := fs.IsNonAIDomain(tt.domain)
			if got != tt.shouldBlock {
				t.Errorf("IsNonAIDomain(%q) = %v, want %v", tt.domain, got, tt.shouldBlock)
			}
		})
	}
}

func TestFilterSetSaveLoad(t *testing.T) {
	withTempFilterSet(t, func(fs *FilterSet, path string) {
		fs.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
		fs.AddAgent("openai", "python*", []string{"*.openai.com", "api.openai.com"})
		fs.AddNonAIDomain("google.com")
		fs.AddNonAIDomain("apple.com")

		if err := fs.Save(path); err != nil {
			t.Fatalf("Save failed: %v", err)
		}

		loaded := NewFilterSet()
		if err := loaded.Load(path); err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		if loaded.MatchAgent("claude-code", "api.anthropic.com") == "" {
			t.Error("loaded FilterSet should match claude agent")
		}
		if loaded.MatchAgent("python3", "api.openai.com") == "" {
			t.Error("loaded FilterSet should match openai agent")
		}
		if !loaded.IsNonAIDomain("google.com") {
			t.Error("loaded FilterSet should have google.com in non-AI")
		}
		if !loaded.IsNonAIDomain("api.apple.com") {
			t.Error("loaded FilterSet should block apple.com subdomains")
		}
	})
}

func TestDomainNormalization(t *testing.T) {
	fs := NewFilterSet()
	fs.AddAgent("test", "*", []string{"example.com"})

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
			got := fs.MatchAgent("test", tt.domain)
			if tt.shouldMatch && got == "" {
				t.Errorf("expected match for %q", tt.domain)
			}
		})
	}
}

func TestMatchAgentPriority(t *testing.T) {
	fs := NewFilterSet()
	fs.AddAgent("first", "*", []string{"*.example.com"})
	fs.AddAgent("second", "*", []string{"*.example.com"})

	got := fs.MatchAgent("test", "api.example.com")
	if got != "first" {
		t.Errorf("first matching agent should win, got %q", got)
	}
}

func TestEmptyFilterSet(t *testing.T) {
	fs := NewFilterSet()

	if fs.MatchAgent("curl", "api.openai.com") != "" {
		t.Error("empty FilterSet should not match any agent")
	}

	if fs.IsNonAIDomain("google.com") {
		t.Error("empty FilterSet should not have any non-AI domains")
	}

	if fs.IsNonAI("curl", "google.com") {
		t.Error("empty FilterSet should not have any non-AI entries")
	}
}

func TestAddAgentDomain(t *testing.T) {
	fs := NewFilterSet()
	fs.AddAgent("test", "curl", []string{"api.example.com"})
	fs.AddAgentDomain("test", "api.other.com")

	if fs.MatchAgent("curl", "api.example.com") == "" {
		t.Error("should match original domain")
	}
	if fs.MatchAgent("curl", "api.other.com") == "" {
		t.Error("should match added domain")
	}
}

func TestAddAgentDomainNonExistent(t *testing.T) {
	fs := NewFilterSet()
	fs.AddAgentDomain("nonexistent", "api.example.com")

	agents := fs.ListAgents()
	if len(agents) != 0 {
		t.Error("adding domain to non-existent agent should not create agent")
	}
}

func TestRemoveAgent(t *testing.T) {
	fs := NewFilterSet()
	fs.AddAgent("test", "curl", []string{"api.example.com"})

	if fs.MatchAgent("curl", "api.example.com") == "" {
		t.Error("agent should match before removal")
	}

	fs.RemoveAgent("test")

	if fs.MatchAgent("curl", "api.example.com") != "" {
		t.Error("agent should not match after removal")
	}
}

func TestRemoveIgnoredDomain(t *testing.T) {
	fs := NewFilterSet()
	fs.AddNonAIDomain("google.com")

	if !fs.IsNonAIDomain("google.com") {
		t.Error("domain should be ignored")
	}

	fs.RemoveIgnoredDomain("google.com")

	domains := fs.ListIgnoredDomains()
	for _, d := range domains {
		if d == "google.com" {
			t.Error("google.com should be removed from list")
		}
	}
}

func TestNonAIProcessDomain(t *testing.T) {
	fs := NewFilterSet()
	fs.AddNonAI("Safari", "apple.com")

	if !fs.IsNonAI("Safari", "apple.com") {
		t.Error("exact process+domain should be non-AI")
	}

	if !fs.IsNonAI("safari", "APPLE.COM") {
		t.Error("IsNonAI should be case insensitive")
	}
}
