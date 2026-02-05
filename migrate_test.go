//go:build darwin || linux

package sai

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDBPathMigration(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")
	newDir := filepath.Join(dir, ".config", "agentsonar")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyDB := filepath.Join(legacyDir, "sai.db")
	if err := os.WriteFile(legacyDB, []byte("test db content"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)
	t.Setenv("AGENTSONAR_DB_PATH", "")
	t.Setenv("SAI_DB_PATH", "")

	path := DefaultDBPath()
	expectedPath := filepath.Join(newDir, "agentsonar.db")

	if path != expectedPath {
		t.Errorf("DefaultDBPath() = %q, want %q", path, expectedPath)
	}

	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Error("migration should have created new db file")
	}

	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "test db content" {
		t.Errorf("migrated content = %q, want %q", string(content), "test db content")
	}
}

func TestLegacyOverridesPathMigration(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")
	newDir := filepath.Join(dir, ".config", "agentsonar")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyOverrides := filepath.Join(legacyDir, "overrides.bin")
	if err := os.WriteFile(legacyOverrides, []byte("test overrides"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)
	t.Setenv("AGENTSONAR_OVERRIDES_PATH", "")
	t.Setenv("SAI_OVERRIDES_PATH", "")

	path := DefaultOverridesPath()
	expectedPath := filepath.Join(newDir, "overrides.bin")

	if path != expectedPath {
		t.Errorf("DefaultOverridesPath() = %q, want %q", path, expectedPath)
	}

	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Error("migration should have created new overrides file")
	}

	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "test overrides" {
		t.Errorf("migrated content = %q, want %q", string(content), "test overrides")
	}
}

func TestLegacyEnvVarDBFallback(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "legacy.db")

	t.Setenv("AGENTSONAR_DB_PATH", "")
	t.Setenv("SAI_DB_PATH", legacyPath)

	path := DefaultDBPath()
	if path != legacyPath {
		t.Errorf("DefaultDBPath() = %q, want %q (legacy env var)", path, legacyPath)
	}
}

func TestNewEnvVarTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	newPath := filepath.Join(dir, "new.db")
	legacyPath := filepath.Join(dir, "legacy.db")

	t.Setenv("AGENTSONAR_DB_PATH", newPath)
	t.Setenv("SAI_DB_PATH", legacyPath)

	path := DefaultDBPath()
	if path != newPath {
		t.Errorf("DefaultDBPath() = %q, want %q (new env var should take precedence)", path, newPath)
	}
}

func TestLegacyEnvVarOverridesFallback(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "legacy_overrides.bin")

	t.Setenv("AGENTSONAR_OVERRIDES_PATH", "")
	t.Setenv("SAI_OVERRIDES_PATH", legacyPath)

	path := DefaultOverridesPath()
	if path != legacyPath {
		t.Errorf("DefaultOverridesPath() = %q, want %q (legacy env var)", path, legacyPath)
	}
}

func TestNewEnvVarOverridesTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	newPath := filepath.Join(dir, "new_overrides.bin")
	legacyPath := filepath.Join(dir, "legacy_overrides.bin")

	t.Setenv("AGENTSONAR_OVERRIDES_PATH", newPath)
	t.Setenv("SAI_OVERRIDES_PATH", legacyPath)

	path := DefaultOverridesPath()
	if path != newPath {
		t.Errorf("DefaultOverridesPath() = %q, want %q (new env var should take precedence)", path, newPath)
	}
}

func TestMigrationDoesNotOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")
	newDir := filepath.Join(dir, ".config", "agentsonar")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyDB := filepath.Join(legacyDir, "sai.db")
	newDB := filepath.Join(newDir, "agentsonar.db")

	if err := os.WriteFile(legacyDB, []byte("old content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newDB, []byte("new content"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)
	t.Setenv("AGENTSONAR_DB_PATH", "")
	t.Setenv("SAI_DB_PATH", "")

	_ = DefaultDBPath()

	content, err := os.ReadFile(newDB)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new content" {
		t.Errorf("existing file was overwritten: got %q, want %q", string(content), "new content")
	}
}

func TestOverridesFileExistsChecksLegacy(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyOverrides := filepath.Join(legacyDir, "overrides.bin")
	if err := os.WriteFile(legacyOverrides, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)
	t.Setenv("AGENTSONAR_OVERRIDES_PATH", "")
	t.Setenv("SAI_OVERRIDES_PATH", "")

	if !OverridesFileExists() {
		t.Error("OverridesFileExists() should return true when legacy file exists")
	}
}

func TestLegacyConfigDirEnvVar(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, "legacy_config")

	t.Setenv("AGENTSONAR_CONFIG_DIR", "")
	t.Setenv("SAI_CONFIG_DIR", legacyDir)

	result := ResolveLegacyEnvConfigDir()
	if result != legacyDir {
		t.Errorf("ResolveLegacyEnvConfigDir() = %q, want %q", result, legacyDir)
	}
}

func TestNewConfigDirEnvVarTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	newDir := filepath.Join(dir, "new_config")
	legacyDir := filepath.Join(dir, "legacy_config")

	t.Setenv("AGENTSONAR_CONFIG_DIR", newDir)
	t.Setenv("SAI_CONFIG_DIR", legacyDir)

	result := ResolveLegacyEnvConfigDir()
	if result != newDir {
		t.Errorf("ResolveLegacyEnvConfigDir() = %q, want %q", result, newDir)
	}
}

func TestMigrateDBFunction(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")
	newDir := filepath.Join(dir, ".config", "agentsonar")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyDB := filepath.Join(legacyDir, "sai.db")
	if err := os.WriteFile(legacyDB, []byte("db data"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)

	if err := MigrateDB(); err != nil {
		t.Fatalf("MigrateDB() error = %v", err)
	}

	newDB := filepath.Join(newDir, "agentsonar.db")
	content, err := os.ReadFile(newDB)
	if err != nil {
		t.Fatalf("could not read migrated db: %v", err)
	}
	if string(content) != "db data" {
		t.Errorf("migrated content = %q, want %q", string(content), "db data")
	}
}

func TestMigrateOverridesFunction(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, ".config", "sai")
	newDir := filepath.Join(dir, ".config", "agentsonar")

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}

	legacyOverrides := filepath.Join(legacyDir, "overrides.bin")
	if err := os.WriteFile(legacyOverrides, []byte("overrides data"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", dir)

	if err := MigrateOverrides(); err != nil {
		t.Fatalf("MigrateOverrides() error = %v", err)
	}

	newOverrides := filepath.Join(newDir, "overrides.bin")
	content, err := os.ReadFile(newOverrides)
	if err != nil {
		t.Fatalf("could not read migrated overrides: %v", err)
	}
	if string(content) != "overrides data" {
		t.Errorf("migrated content = %q, want %q", string(content), "overrides data")
	}
}

func TestMigrateNonExistentFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := MigrateDB(); err != nil {
		t.Errorf("MigrateDB() should not error for non-existent source: %v", err)
	}

	if err := MigrateOverrides(); err != nil {
		t.Errorf("MigrateOverrides() should not error for non-existent source: %v", err)
	}
}
