package sai

import (
	"io"
	"os"
	"path/filepath"
)

const (
	legacyConfigDir   = "sai"
	legacyDBFile      = "sai.db"
	legacyOverrides   = "overrides.bin"
	legacyPidFile     = "sai.pid"
	legacyLogFile     = "sai.log"
	legacyEnvDB       = "SAI_DB_PATH"
	legacyEnvOverride = "SAI_OVERRIDES_PATH"
	legacyEnvConfig   = "SAI_CONFIG_DIR"
)

func legacyDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", legacyConfigDir, legacyDBFile)
}

func legacyOverridesPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", legacyConfigDir, legacyOverrides)
}

func migrateFile(src, dst string) error {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil
	}
	if _, err := os.Stat(dst); err == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return nil
}

func MigrateDB() error {
	return migrateFile(legacyDBPath(), defaultDBPathNew())
}

func MigrateOverrides() error {
	return migrateFile(legacyOverridesPath(), defaultOverridesPathNew())
}

func defaultDBPathNew() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agentsonar", "agentsonar.db")
}

func defaultOverridesPathNew() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agentsonar", "overrides.bin")
}

func resolveLegacyEnvDB() string {
	if p := os.Getenv("AGENTSONAR_DB_PATH"); p != "" {
		return p
	}
	if p := os.Getenv(legacyEnvDB); p != "" {
		return p
	}
	return ""
}

func resolveLegacyEnvOverrides() string {
	if p := os.Getenv("AGENTSONAR_OVERRIDES_PATH"); p != "" {
		return p
	}
	if p := os.Getenv(legacyEnvOverride); p != "" {
		return p
	}
	return ""
}

func ResolveLegacyEnvConfigDir() string {
	if p := os.Getenv("AGENTSONAR_CONFIG_DIR"); p != "" {
		return p
	}
	if p := os.Getenv(legacyEnvConfig); p != "" {
		return p
	}
	return ""
}
