//go:build linux

package sai

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

func CheckPermissions() error {
	if os.Geteuid() == 0 {
		return nil
	}
	if hasNetCapabilities() {
		return nil
	}
	return &PermissionError{
		Reason:   ReasonCapability,
		Platform: runtime.GOOS,
	}
}

func hasNetCapabilities() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "CapEff:") {
			capHex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			return parseCapabilities(capHex)
		}
	}
	return false
}

func parseCapabilities(capHex string) bool {
	if len(capHex) < 4 {
		return false
	}
	lastFour := capHex[len(capHex)-4:]
	var capVal uint64
	for _, c := range lastFour {
		capVal <<= 4
		switch {
		case c >= '0' && c <= '9':
			capVal |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			capVal |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			capVal |= uint64(c - 'A' + 10)
		}
	}
	capNetRaw := uint64(1) << 13
	capNetAdmin := uint64(1) << 12
	return (capVal&capNetRaw != 0) && (capVal&capNetAdmin != 0)
}

func wrapPermissionError(err error) error {
	if err == nil {
		return nil
	}
	if !isPermissionError(err) {
		return nil
	}
	return &PermissionError{
		Reason:   ReasonCapability,
		Platform: runtime.GOOS,
		Err:      err,
	}
}
