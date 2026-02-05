package sai

import (
	"errors"
	"testing"
)

func TestPermissionError(t *testing.T) {
	tests := []struct {
		name       string
		err        *PermissionError
		wantMsg    string
		wantHint   string
		wantReason string
	}{
		{
			name: "BPF group error without wrapped error",
			err: &PermissionError{
				Reason:   ReasonBPFGroup,
				Platform: "darwin",
			},
			wantMsg:    "user not in access_bpf group",
			wantHint:   "run 'agentsonar install' to configure BPF permissions",
			wantReason: "user not in access_bpf group",
		},
		{
			name: "BPF access error with wrapped error",
			err: &PermissionError{
				Reason:   ReasonBPFAccess,
				Platform: "darwin",
				Err:      errors.New("permission denied"),
			},
			wantMsg:    "BPF device not accessible: permission denied",
			wantHint:   "run 'agentsonar install' to configure BPF permissions",
			wantReason: "BPF device not accessible",
		},
		{
			name: "Linux capability error",
			err: &PermissionError{
				Reason:   ReasonCapability,
				Platform: "linux",
			},
			wantMsg:    "missing network capture capabilities",
			wantHint:   "run 'agentsonar install' to configure capture capabilities",
			wantReason: "missing network capture capabilities",
		},
		{
			name: "unknown reason",
			err: &PermissionError{
				Reason:   ReasonUnknown,
				Platform: "darwin",
			},
			wantMsg:    "unknown permission issue",
			wantHint:   "run 'agentsonar install' to configure permissions",
			wantReason: "unknown permission issue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
			if got := tt.err.Hint(); got != tt.wantHint {
				t.Errorf("Hint() = %q, want %q", got, tt.wantHint)
			}
			if got := tt.err.Reason.String(); got != tt.wantReason {
				t.Errorf("Reason.String() = %q, want %q", got, tt.wantReason)
			}
		})
	}
}

func TestPermissionErrorUnwrap(t *testing.T) {
	inner := errors.New("underlying error")
	err := &PermissionError{
		Reason:   ReasonBPFAccess,
		Platform: "darwin",
		Err:      inner,
	}

	if unwrapped := err.Unwrap(); unwrapped != inner {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, inner)
	}

	if !errors.Is(err, inner) {
		t.Error("errors.Is should find the wrapped error")
	}
}

func TestIsPermissionError(t *testing.T) {
	permErr := &PermissionError{
		Reason:   ReasonBPFGroup,
		Platform: "darwin",
	}

	wrappedErr := errors.New("wrapped: " + permErr.Error())
	_ = wrappedErr

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct PermissionError",
			err:  permErr,
			want: true,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "regular error",
			err:  errors.New("some error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermissionError(tt.err); got != tt.want {
				t.Errorf("IsPermissionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPermissions(t *testing.T) {
	err := CheckPermissions()
	if err != nil {
		var permErr *PermissionError
		if !errors.As(err, &permErr) {
			t.Errorf("CheckPermissions() returned non-PermissionError: %T", err)
		}
	}
}
