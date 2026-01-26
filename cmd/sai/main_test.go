package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knostic/sai"
	"github.com/spf13/cobra"
)

func withTestEnv(t *testing.T, fn func(dir string)) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SAI_DB_PATH", filepath.Join(dir, "sai.db"))
	t.Setenv("SAI_OVERRIDES_PATH", filepath.Join(dir, "overrides.bin"))
	t.Setenv("SAI_CONFIG_DIR", dir)
	fn(dir)
}

func runCmd(cmd *cobra.Command, args ...string) (string, string, error) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestAgentsAddAndList(t *testing.T) {
	withTestEnv(t, func(dir string) {
		filterSet := sai.NewOverrides()
		filterSet.AddAgent("test-agent", "python*", []string{"*.openai.com"})
		filterSet.Save(sai.DefaultOverridesPath())

		loaded := loadOverrides()
		agents := loaded.ListAgents()

		if len(agents) != 1 {
			t.Fatalf("expected 1 agent, got %d", len(agents))
		}
		if agents[0].Name != "test-agent" {
			t.Errorf("agent name = %q, want %q", agents[0].Name, "test-agent")
		}
		if agents[0].Process != "python*" {
			t.Errorf("agent process = %q, want %q", agents[0].Process, "python*")
		}
		if len(agents[0].Domains) != 1 || agents[0].Domains[0] != "*.openai.com" {
			t.Errorf("agent domains = %v, want [*.openai.com]", agents[0].Domains)
		}
	})
}

func TestAgentsAddDomain(t *testing.T) {
	withTestEnv(t, func(dir string) {
		filterSet := sai.NewOverrides()
		filterSet.AddAgent("test-agent", "python*", []string{"*.openai.com"})
		filterSet.Save(sai.DefaultOverridesPath())

		loaded := loadOverrides()
		loaded.AddAgentDomain("test-agent", "api.anthropic.com")
		saveOverrides(loaded)

		reloaded := loadOverrides()
		agent := reloaded.GetAgent("test-agent")

		if agent == nil {
			t.Fatal("agent not found")
		}
		if len(agent.Domains) != 2 {
			t.Errorf("expected 2 domains, got %d", len(agent.Domains))
		}

		found := false
		for _, d := range agent.Domains {
			if d == "api.anthropic.com" {
				found = true
				break
			}
		}
		if !found {
			t.Error("api.anthropic.com not found in domains")
		}
	})
}

func TestAgentsAddDomainNonExistent(t *testing.T) {
	withTestEnv(t, func(dir string) {
		filterSet := sai.NewOverrides()
		filterSet.Save(sai.DefaultOverridesPath())

		loaded := loadOverrides()
		if loaded.GetAgent("nonexistent") != nil {
			t.Error("nonexistent agent should not exist")
		}
	})
}

func TestAgentsRemove(t *testing.T) {
	withTestEnv(t, func(dir string) {
		filterSet := sai.NewOverrides()
		filterSet.AddAgent("test-agent", "python*", []string{"*.openai.com"})
		filterSet.Save(sai.DefaultOverridesPath())

		loaded := loadOverrides()
		loaded.RemoveAgent("test-agent")
		saveOverrides(loaded)

		reloaded := loadOverrides()
		agents := reloaded.ListAgents()

		if len(agents) != 0 {
			t.Errorf("expected 0 agents after removal, got %d", len(agents))
		}
	})
}

func TestIgnoreCommand(t *testing.T) {
	withTestEnv(t, func(dir string) {
		filterSet := sai.NewOverrides()
		filterSet.AddNoise("google.com")
		filterSet.Save(sai.DefaultOverridesPath())

		loaded := loadOverrides()

		if !loaded.IsNoise("google.com") {
			t.Error("google.com should be ignored")
		}
		if !loaded.IsNoise("api.google.com") {
			t.Error("api.google.com should be ignored (subdomain)")
		}
	})
}

func TestIgnoreRemove(t *testing.T) {
	withTestEnv(t, func(dir string) {
		filterSet := sai.NewOverrides()
		filterSet.AddNoise("google.com")
		filterSet.Save(sai.DefaultOverridesPath())

		loaded := loadOverrides()
		loaded.RemoveNoise("google.com")
		saveOverrides(loaded)

		reloaded := loadOverrides()
		domains := reloaded.ListNoise()

		for _, d := range domains {
			if d == "google.com" {
				t.Error("google.com should be removed")
			}
		}
	})
}

func TestEventsCommand(t *testing.T) {
	withTestEnv(t, func(dir string) {
		db, err := sai.OpenDB(sai.DefaultDBPath())
		if err != nil {
			t.Fatalf("OpenDB failed: %v", err)
		}

		events := []sai.Event{
			{Timestamp: time.Now(), PID: 1, Process: "curl", Domain: "api.openai.com", Source: "tls"},
			{Timestamp: time.Now(), PID: 2, Process: "python3", Domain: "api.anthropic.com", Source: "tls"},
		}
		for _, e := range events {
			db.InsertEvent(e)
		}
		db.Close()

		db, _ = sai.OpenDB(sai.DefaultDBPath())
		defer db.Close()

		results, err := db.QueryEvents(0, "", "", 0)
		if err != nil {
			t.Fatalf("QueryEvents failed: %v", err)
		}
		if len(results) != 2 {
			t.Errorf("expected 2 events, got %d", len(results))
		}
	})
}

func TestEventsWithFilters(t *testing.T) {
	withTestEnv(t, func(dir string) {
		db, err := sai.OpenDB(sai.DefaultDBPath())
		if err != nil {
			t.Fatalf("OpenDB failed: %v", err)
		}

		events := []sai.Event{
			{Timestamp: time.Now(), PID: 1, Process: "curl", Domain: "api.openai.com", Source: "tls"},
			{Timestamp: time.Now(), PID: 2, Process: "python3", Domain: "api.openai.com", Source: "tls"},
			{Timestamp: time.Now(), PID: 3, Process: "curl", Domain: "api.anthropic.com", Source: "tls"},
		}
		for _, e := range events {
			db.InsertEvent(e)
		}
		db.Close()

		db, _ = sai.OpenDB(sai.DefaultDBPath())
		defer db.Close()

		results, _ := db.QueryEvents(0, "curl", "", 0)
		if len(results) != 2 {
			t.Errorf("process filter: expected 2, got %d", len(results))
		}

		results, _ = db.QueryEvents(0, "", "openai", 0)
		if len(results) != 2 {
			t.Errorf("domain filter: expected 2, got %d", len(results))
		}

		results, _ = db.QueryEvents(0, "curl", "anthropic", 0)
		if len(results) != 1 {
			t.Errorf("combined filter: expected 1, got %d", len(results))
		}
	})
}

func TestEventsJSONOutput(t *testing.T) {
	withTestEnv(t, func(dir string) {
		db, err := sai.OpenDB(sai.DefaultDBPath())
		if err != nil {
			t.Fatalf("OpenDB failed: %v", err)
		}

		event := sai.Event{
			Timestamp: time.Now(),
			PID:       123,
			Process:   "test",
			Domain:    "example.com",
			Source:    "tls",
		}
		db.InsertEvent(event)
		db.Close()

		db, _ = sai.OpenDB(sai.DefaultDBPath())
		defer db.Close()

		results, _ := db.QueryEvents(0, "", "", 1)
		if len(results) != 1 {
			t.Fatal("expected 1 event")
		}

		jsonData, err := json.Marshal(results[0])
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var decoded sai.Event
		if err := json.Unmarshal(jsonData, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if decoded.Process != "test" {
			t.Errorf("process = %q, want %q", decoded.Process, "test")
		}
	})
}

func TestEventsLimit(t *testing.T) {
	withTestEnv(t, func(dir string) {
		db, err := sai.OpenDB(sai.DefaultDBPath())
		if err != nil {
			t.Fatalf("OpenDB failed: %v", err)
		}

		for i := 0; i < 10; i++ {
			db.InsertEvent(sai.Event{
				Timestamp: time.Now(),
				PID:       i,
				Process:   "test",
				Domain:    "example.com",
				Source:    "tls",
			})
		}
		db.Close()

		db, _ = sai.OpenDB(sai.DefaultDBPath())
		defer db.Close()

		results, _ := db.QueryEvents(0, "", "", 5)
		if len(results) != 5 {
			t.Errorf("limit 5: expected 5, got %d", len(results))
		}
	})
}

func TestSigExportImport(t *testing.T) {
	withTestEnv(t, func(dir string) {
		filterSet := sai.NewOverrides()
		filterSet.AddAgent("test-agent", "python*", []string{"*.openai.com"})
		filterSet.AddNoise("google.com")
		filterSet.Save(sai.DefaultOverridesPath())

		exportPath := filepath.Join(dir, "export.bin")

		src, err := os.Open(sai.DefaultOverridesPath())
		if err != nil {
			t.Fatalf("open source failed: %v", err)
		}
		dst, err := os.Create(exportPath)
		if err != nil {
			src.Close()
			t.Fatalf("create export failed: %v", err)
		}
		_, err = dst.ReadFrom(src)
		src.Close()
		dst.Close()
		if err != nil {
			t.Fatalf("copy failed: %v", err)
		}

		os.Remove(sai.DefaultOverridesPath())

		src, err = os.Open(exportPath)
		if err != nil {
			t.Fatalf("open export failed: %v", err)
		}
		dst, err = os.Create(sai.DefaultOverridesPath())
		if err != nil {
			src.Close()
			t.Fatalf("create import failed: %v", err)
		}
		_, err = dst.ReadFrom(src)
		src.Close()
		dst.Close()
		if err != nil {
			t.Fatalf("import copy failed: %v", err)
		}

		loaded := loadOverrides()
		if loaded.MatchAgent("python3", "api.openai.com") == "" {
			t.Error("imported filters should match agent")
		}
		if !loaded.IsNoise("google.com") {
			t.Error("imported filters should have non-AI domain")
		}
	})
}

func TestSigImportMissingFile(t *testing.T) {
	_, err := os.Stat("/nonexistent/path/file.bin")
	if err == nil {
		t.Error("missing file should return error")
	}
}

func TestClassifierList(t *testing.T) {
	registry := sai.NewClassifierRegistry()
	registry.Add(sai.NewDefaultClassifier())

	names := registry.List()
	if len(names) != 1 {
		t.Errorf("expected 1 classifier, got %d", len(names))
	}
	if names[0] != "default" {
		t.Errorf("classifier name = %q, want %q", names[0], "default")
	}
}

func TestClassifierLoadInvalid(t *testing.T) {
	withTestEnv(t, func(dir string) {
		invalidConfig := filepath.Join(dir, "invalid.json")
		os.WriteFile(invalidConfig, []byte("not valid json"), 0644)

		_, err := sai.LoadProcessClassifier(invalidConfig)
		if err == nil {
			t.Error("loading invalid config should fail")
		}
	})
}

func TestDoctorComponents(t *testing.T) {
	withTestEnv(t, func(dir string) {
		db, err := sai.OpenDB(sai.DefaultDBPath())
		if err != nil {
			t.Fatalf("OpenDB failed: %v", err)
		}
		db.Close()

		filterSet := sai.NewOverrides()
		filterSet.AddAgent("test", "test*", []string{"*.test.com"})
		filterSet.Save(sai.DefaultOverridesPath())

		if !sai.OverridesFileExists() {
			t.Error("filters file should exist")
		}

		dbPath := sai.DefaultDBPath()
		if !strings.Contains(dbPath, dir) {
			t.Errorf("DB path %q should contain temp dir %q", dbPath, dir)
		}

		filterPath := sai.DefaultOverridesPath()
		if !strings.Contains(filterPath, dir) {
			t.Errorf("filter path %q should contain temp dir %q", filterPath, dir)
		}
	})
}

func TestOverridesRoundTrip(t *testing.T) {
	withTestEnv(t, func(dir string) {
		fs := sai.NewOverrides()
		fs.AddAgent("agent1", "proc1*", []string{"*.dom1.com"})
		fs.AddAgent("agent2", "proc2*", []string{"*.dom2.com", "api.dom2.com"})
		fs.AddNoise("ignored1.com")
		fs.AddNoise("ignored2.com")

		if err := fs.Save(sai.DefaultOverridesPath()); err != nil {
			t.Fatalf("save failed: %v", err)
		}

		loaded := sai.NewOverrides()
		if err := loaded.Load(sai.DefaultOverridesPath()); err != nil {
			t.Fatalf("load failed: %v", err)
		}

		agents := loaded.ListAgents()
		if len(agents) != 2 {
			t.Errorf("expected 2 agents, got %d", len(agents))
		}

		ignored := loaded.ListNoise()
		if len(ignored) != 2 {
			t.Errorf("expected 2 ignored domains, got %d", len(ignored))
		}

		if loaded.MatchAgent("proc1-test", "api.dom1.com") != "agent1" {
			t.Error("should match agent1")
		}
		if loaded.MatchAgent("proc2-test", "api.dom2.com") != "agent2" {
			t.Error("should match agent2")
		}
		if !loaded.IsNoise("ignored1.com") {
			t.Error("ignored1.com should be non-AI")
		}
		if !loaded.IsNoise("sub.ignored2.com") {
			t.Error("sub.ignored2.com should be non-AI")
		}
	})
}

func TestPathEnvVars(t *testing.T) {
	dir := t.TempDir()
	customDB := filepath.Join(dir, "custom.db")
	customFilter := filepath.Join(dir, "custom.bin")

	t.Setenv("SAI_DB_PATH", customDB)
	t.Setenv("SAI_OVERRIDES_PATH", customFilter)

	if sai.DefaultDBPath() != customDB {
		t.Errorf("DefaultDBPath() = %q, want %q", sai.DefaultDBPath(), customDB)
	}
	if sai.DefaultOverridesPath() != customFilter {
		t.Errorf("DefaultOverridesPath() = %q, want %q", sai.DefaultOverridesPath(), customFilter)
	}
}

func TestPidAndLogPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SAI_CONFIG_DIR", dir)

	pid := pidPath()
	if !strings.HasPrefix(pid, dir) {
		t.Errorf("pidPath() = %q, should start with %q", pid, dir)
	}
	if !strings.HasSuffix(pid, "sai.pid") {
		t.Errorf("pidPath() = %q, should end with sai.pid", pid)
	}

	log := logPath()
	if !strings.HasPrefix(log, dir) {
		t.Errorf("logPath() = %q, should start with %q", log, dir)
	}
	if !strings.HasSuffix(log, "sai.log") {
		t.Errorf("logPath() = %q, should end with sai.log", log)
	}
}
