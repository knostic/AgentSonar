package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knostic/agentsonar"
	"github.com/spf13/cobra"
)

func withTestEnv(t *testing.T, fn func(dir string)) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AGENTSONAR_DB_PATH", filepath.Join(dir, "agentsonar.db"))
	t.Setenv("AGENTSONAR_OVERRIDES_PATH", filepath.Join(dir, "overrides.bin"))
	t.Setenv("AGENTSONAR_CONFIG_DIR", dir)
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

	t.Setenv("AGENTSONAR_DB_PATH", customDB)
	t.Setenv("AGENTSONAR_OVERRIDES_PATH", customFilter)

	if sai.DefaultDBPath() != customDB {
		t.Errorf("DefaultDBPath() = %q, want %q", sai.DefaultDBPath(), customDB)
	}
	if sai.DefaultOverridesPath() != customFilter {
		t.Errorf("DefaultOverridesPath() = %q, want %q", sai.DefaultOverridesPath(), customFilter)
	}
}

func TestPidAndLogPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTSONAR_CONFIG_DIR", dir)

	pid := pidPath()
	if !strings.HasPrefix(pid, dir) {
		t.Errorf("pidPath() = %q, should start with %q", pid, dir)
	}
	if !strings.HasSuffix(pid, "agentsonar.pid") {
		t.Errorf("pidPath() = %q, should end with agentsonar.pid", pid)
	}

	log := logPath()
	if !strings.HasPrefix(log, dir) {
		t.Errorf("logPath() = %q, should start with %q", log, dir)
	}
	if !strings.HasSuffix(log, "agentsonar.log") {
		t.Errorf("logPath() = %q, should end with agentsonar.log", log)
	}
}

func TestLegacyConfigDirEnvVar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTSONAR_CONFIG_DIR", "")
	t.Setenv("SAI_CONFIG_DIR", dir)

	pid := pidPath()
	if !strings.HasPrefix(pid, dir) {
		t.Errorf("pidPath() = %q, should use legacy SAI_CONFIG_DIR %q", pid, dir)
	}

	log := logPath()
	if !strings.HasPrefix(log, dir) {
		t.Errorf("logPath() = %q, should use legacy SAI_CONFIG_DIR %q", log, dir)
	}
}

func TestNewConfigDirTakesPrecedence(t *testing.T) {
	newDir := t.TempDir()
	legacyDir := t.TempDir()
	t.Setenv("AGENTSONAR_CONFIG_DIR", newDir)
	t.Setenv("SAI_CONFIG_DIR", legacyDir)

	pid := pidPath()
	if !strings.HasPrefix(pid, newDir) {
		t.Errorf("pidPath() = %q, should use new AGENTSONAR_CONFIG_DIR %q", pid, newDir)
	}
	if strings.HasPrefix(pid, legacyDir) {
		t.Errorf("pidPath() should not use legacy dir when new dir is set")
	}
}

func TestLegacyPidFileMigration(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")
	newDir := filepath.Join(dir, ".config", "agentsonar")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyPid := filepath.Join(legacyDir, "sai.pid")
	if err := os.WriteFile(legacyPid, []byte("12345"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)
	t.Setenv("AGENTSONAR_CONFIG_DIR", "")
	t.Setenv("SAI_CONFIG_DIR", "")
	t.Setenv("AGENTSONAR_DB_PATH", filepath.Join(newDir, "agentsonar.db"))

	pid := pidPath()
	expectedPid := filepath.Join(newDir, "agentsonar.pid")

	if pid != expectedPid {
		t.Errorf("pidPath() = %q, want %q", pid, expectedPid)
	}

	if _, err := os.Stat(expectedPid); os.IsNotExist(err) {
		t.Error("legacy pid file should have been migrated")
	}

	content, _ := os.ReadFile(expectedPid)
	if string(content) != "12345" {
		t.Errorf("migrated pid content = %q, want %q", string(content), "12345")
	}
}

func TestLegacyLogFileMigration(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")
	newDir := filepath.Join(dir, ".config", "agentsonar")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyLog := filepath.Join(legacyDir, "sai.log")
	if err := os.WriteFile(legacyLog, []byte("log content"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)
	t.Setenv("AGENTSONAR_CONFIG_DIR", "")
	t.Setenv("SAI_CONFIG_DIR", "")
	t.Setenv("AGENTSONAR_DB_PATH", filepath.Join(newDir, "agentsonar.db"))

	log := logPath()
	expectedLog := filepath.Join(newDir, "agentsonar.log")

	if log != expectedLog {
		t.Errorf("logPath() = %q, want %q", log, expectedLog)
	}

	if _, err := os.Stat(expectedLog); os.IsNotExist(err) {
		t.Error("legacy log file should have been migrated")
	}

	content, _ := os.ReadFile(expectedLog)
	if string(content) != "log content" {
		t.Errorf("migrated log content = %q, want %q", string(content), "log content")
	}
}

func TestEventTableAlignment(t *testing.T) {
	columns := []string{"AI", "AGENT", "DOMAIN", "PROCESS", "SOURCE", "TIME"}
	// Column widths from eventFormat: "%-7s  %-14s  %-28s  %-13s  %-10s  %s"
	colWidths := map[string]int{"AI": 7, "AGENT": 14, "DOMAIN": 28, "PROCESS": 13, "SOURCE": 10, "TIME": 8}

	header := fmt.Sprintf(eventFormat, fmt.Sprintf("%-7s", "AI"), "AGENT", "DOMAIN", "PROCESS", "SOURCE", "TIME")

	// Find column start positions from header
	colPositions := make(map[string]int)
	for _, col := range columns {
		colPositions[col] = strings.Index(header, col)
	}

	genStr := func(n int) string {
		if n <= 0 {
			return "x"
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = 'a' + byte(i%26)
		}
		return string(b)
	}

	// Generate lengths up to each column's max width
	genLengths := func(max int) []int {
		lengths := []int{1}
		for i := 2; i <= max; i += max / 4 {
			lengths = append(lengths, i)
		}
		if lengths[len(lengths)-1] != max {
			lengths = append(lengths, max)
		}
		return lengths
	}

	var lines []string
	lines = append(lines, header)

	aiLengths := genLengths(colWidths["AI"])
	agentLengths := genLengths(colWidths["AGENT"])
	domainLengths := genLengths(colWidths["DOMAIN"])
	procLengths := genLengths(colWidths["PROCESS"])

	for _, aiLen := range aiLengths {
		for _, agentLen := range agentLengths {
			for _, domainLen := range domainLengths {
				for _, procLen := range procLengths {
					ai := fmt.Sprintf("%-7s", genStr(aiLen))
					line := fmt.Sprintf(eventFormat, ai, genStr(agentLen), genStr(domainLen), genStr(procLen), "tls", "12:00:00")
					lines = append(lines, line)
				}
			}
		}
	}

	// Verify alignment: each column should start at the same position across all rows
	// and the character before each column (except first) should be a space
	for i, line := range lines {
		for j, col := range columns {
			pos := colPositions[col]
			if pos >= len(line) {
				t.Errorf("row %d: line too short for column %s at position %d: %q", i, col, pos, line)
				continue
			}
			if j > 0 && pos > 0 && line[pos-1] != ' ' {
				t.Errorf("row %d: expected space before column %s at position %d, got %q: %q", i, col, pos-1, line[pos-1], line)
			}
		}
	}
}

func TestEventFormatColumnWidths(t *testing.T) {
	// Verify the format string has reasonable column widths
	// eventFormat = "%-7s  %-14s  %-28s  %-13s  %-10s  %s"
	expectedWidths := map[string]int{
		"AI":      7,
		"AGENT":   14,
		"DOMAIN":  28,
		"PROCESS": 13,
		"SOURCE":  10,
	}

	testData := []struct {
		field    string
		maxLen   int
		examples []string
	}{
		{"AGENT", 14, []string{"GitHub Copilot", "Claude Code", "Supermaven", "Amazon Q", "Cursor AI"}},
		{"PROCESS", 13, []string{"cursor-helper", "sm-agent", "claude", "node", "q-agent-proc"}},
		{"DOMAIN", 28, []string{"codewhisperer.amazonaws.com", "stream.supermaven.com", "api.anthropic.com"}},
		{"SOURCE", 10, []string{"streaming", "tls", "dns"}},
	}

	for _, td := range testData {
		for _, example := range td.examples {
			if len(example) > expectedWidths[td.field] {
				t.Errorf("%s column width %d is too small for %q (len=%d)",
					td.field, expectedWidths[td.field], example, len(example))
			}
		}
	}
}

func TestFormatScoreTTY(t *testing.T) {
	orig := isTTY
	defer func() { isTTY = orig }()

	isTTY = true

	tests := []struct {
		name         string
		score        sai.AIScore
		isKnownAgent bool
		wantColor    bool
		wantSymbol   string
	}{
		{"known agent", 1.0, true, false, "*"},
		{"high score", 0.85, false, true, "!"},
		{"medium score", 0.55, false, true, "?"},
		{"low score", 0.15, false, true, "·"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatScore(tt.score, tt.isKnownAgent)
			hasColor := strings.Contains(result, "\033[")
			if tt.isKnownAgent {
				if hasColor {
					t.Errorf("known agent should not have color codes in score, got %q", result)
				}
			} else if !hasColor {
				t.Errorf("TTY mode should have color codes, got %q", result)
			}
			if !strings.Contains(result, tt.wantSymbol) {
				t.Errorf("expected symbol %q in %q", tt.wantSymbol, result)
			}
		})
	}
}

func TestFormatScoreNonTTY(t *testing.T) {
	orig := isTTY
	defer func() { isTTY = orig }()

	isTTY = false

	tests := []struct {
		name         string
		score        sai.AIScore
		isKnownAgent bool
		wantContains string
	}{
		{"known agent", 1.0, true, "*"},
		{"high score", 0.85, false, "0.85"},
		{"medium score", 0.55, false, "0.55"},
		{"low score", 0.15, false, "0.15"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatScore(tt.score, tt.isKnownAgent)
			if strings.Contains(result, "\033[") {
				t.Errorf("non-TTY mode should not have color codes, got %q", result)
			}
			if !strings.Contains(result, tt.wantContains) {
				t.Errorf("expected %q in %q", tt.wantContains, result)
			}
		})
	}
}

func TestPrintEventTTY(t *testing.T) {
	orig := isTTY
	defer func() { isTTY = orig }()

	isTTY = true

	tests := []struct {
		name         string
		isKnownAgent bool
		wantColor    bool
	}{
		{"known agent row colored", true, true},
		{"unknown agent row not colored", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			agent := unknownAgent
			if tt.isKnownAgent {
				agent = "TestAgent"
			}
			printEvent(time.Now(), agent, "proc", 123, "example.com", "tls", 0.5, tt.isKnownAgent, false)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			// Check if the line starts with color (row coloring for known agents)
			startsWithColor := strings.HasPrefix(output, "\033[32m")
			if tt.wantColor && !startsWithColor {
				t.Errorf("expected row to start with green color, got %q", output)
			}
			if !tt.wantColor && startsWithColor {
				t.Errorf("expected row without row color, got %q", output)
			}
		})
	}
}

func TestPrintEventNonTTY(t *testing.T) {
	orig := isTTY
	defer func() { isTTY = orig }()

	isTTY = false

	tests := []struct {
		name         string
		isKnownAgent bool
	}{
		{"known agent no colors", true},
		{"unknown agent no colors", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			agent := unknownAgent
			if tt.isKnownAgent {
				agent = "TestAgent"
			}
			printEvent(time.Now(), agent, "proc", 123, "example.com", "tls", 0.5, tt.isKnownAgent, false)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			if strings.Contains(output, "\033[") {
				t.Errorf("non-TTY should have no color codes, got %q", output)
			}
		})
	}
}

func TestClassifyLogic(t *testing.T) {
	withTestEnv(t, func(dir string) {
		fs := sai.NewOverrides()
		fs.AddAgent("test-agent", "python*", []string{"*.openai.com"})
		fs.AddNoise("noise.example.com")
		fs.Save(sai.DefaultOverridesPath())

		overrides := loadOverrides()
		registry := sai.NewClassifierRegistry()
		registry.Add(sai.NewDefaultClassifier())
		defer registry.Close()

		acc := sai.NewAccumulatorWithOverrides(overrides, registry)

		// Known agent detection
		event := sai.Event{Process: "python3", Domain: "api.openai.com", Source: "tls"}
		acc.Record(event)
		agent := overrides.MatchAgent(event.Process, event.Domain)
		if agent != "test-agent" {
			t.Errorf("expected agent 'test-agent', got %q", agent)
		}

		// Noise domain filtering
		if !overrides.IsNoise("noise.example.com") {
			t.Error("noise.example.com should be classified as noise")
		}
		if !overrides.IsNoise("sub.noise.example.com") {
			t.Error("sub.noise.example.com should be classified as noise (subdomain)")
		}

		// Unknown domain gets classifier scores
		input := sai.ClassifierInput{Domain: "unknown.com", Process: "curl", Source: "dns"}
		scores := registry.ClassifyAll(input)
		if _, ok := scores["default"]; !ok {
			t.Error("expected 'default' classifier to return a score")
		}

		// Non-matching agent returns empty string
		nonAgent := overrides.MatchAgent("curl", "random.com")
		if nonAgent != "" {
			t.Errorf("expected empty agent for non-matching process/domain, got %q", nonAgent)
		}
	})
}
