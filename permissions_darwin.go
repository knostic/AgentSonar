//go:build darwin

package sai

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

const bpfGroup = "access_bpf"

func CheckPermissions() error {
	if !canAccessBPF() {
		username := os.Getenv("USER")
		if username == "" {
			if u, err := user.Current(); err == nil {
				username = u.Username
			}
		}
		if username != "" && !userInGroup(username, bpfGroup) {
			return &PermissionError{
				Reason:   ReasonBPFGroup,
				Platform: runtime.GOOS,
			}
		}
		return &PermissionError{
			Reason:   ReasonBPFAccess,
			Platform: runtime.GOOS,
		}
	}
	return nil
}

func canAccessBPF() bool {
	matches, _ := filepath.Glob("/dev/bpf*")
	if len(matches) == 0 {
		return false
	}
	for _, path := range matches {
		f, err := os.OpenFile(path, os.O_RDONLY, 0)
		if err == nil {
			f.Close()
			return true
		}
	}
	return false
}

func userInGroup(username, group string) bool {
	out, err := exec.Command("id", "-Gn", username).Output()
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if g == group {
			return true
		}
	}
	return false
}

func wrapPermissionError(err error) error {
	if err == nil {
		return nil
	}
	if !isPermissionError(err) {
		return nil
	}
	username := os.Getenv("USER")
	if username == "" {
		if u, err := user.Current(); err == nil {
			username = u.Username
		}
	}
	if username != "" && !userInGroup(username, bpfGroup) {
		return &PermissionError{
			Reason:   ReasonBPFGroup,
			Platform: runtime.GOOS,
			Err:      err,
		}
	}
	return &PermissionError{
		Reason:   ReasonBPFAccess,
		Platform: runtime.GOOS,
		Err:      err,
	}
}
