package sai

import (
	"errors"
	"fmt"
	"runtime"
)

type PermissionReason int

const (
	ReasonUnknown PermissionReason = iota
	ReasonBPFAccess   // macOS: /dev/bpf* not readable
	ReasonBPFGroup    // macOS: user not in access_bpf group
	ReasonCapability  // Linux: missing cap_net_raw/cap_net_admin
)

func (r PermissionReason) String() string {
	switch r {
	case ReasonBPFAccess:
		return "BPF device not accessible"
	case ReasonBPFGroup:
		return "user not in access_bpf group"
	case ReasonCapability:
		return "missing network capture capabilities"
	default:
		return "unknown permission issue"
	}
}

type PermissionError struct {
	Reason   PermissionReason
	Platform string
	Err      error
}

func (e *PermissionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Reason, e.Err)
	}
	return e.Reason.String()
}

func (e *PermissionError) Unwrap() error {
	return e.Err
}

func (e *PermissionError) Hint() string {
	switch e.Reason {
	case ReasonBPFAccess, ReasonBPFGroup:
		return "run 'agentsonar install' to configure BPF permissions"
	case ReasonCapability:
		return "run 'agentsonar install' to configure capture capabilities"
	default:
		return "run 'agentsonar install' to configure permissions"
	}
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	switch runtime.GOOS {
	case "darwin":
		return contains(msg, "permission denied") ||
			contains(msg, "you don't have permission") ||
			contains(msg, "Operation not permitted")
	case "linux":
		return contains(msg, "permission denied") ||
			contains(msg, "Operation not permitted") ||
			contains(msg, "EPERM")
	}
	return contains(msg, "permission denied")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if matchAt(s, substr, i) {
			return true
		}
	}
	return false
}

func matchAt(s, substr string, start int) bool {
	for j := 0; j < len(substr); j++ {
		sc := s[start+j]
		pc := substr[j]
		if sc >= 'A' && sc <= 'Z' {
			sc += 32
		}
		if pc >= 'A' && pc <= 'Z' {
			pc += 32
		}
		if sc != pc {
			return false
		}
	}
	return true
}

func IsPermissionError(err error) bool {
	var permErr *PermissionError
	return errors.As(err, &permErr)
}
