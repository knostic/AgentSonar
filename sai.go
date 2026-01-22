// Package sai provides shadow AI detection by monitoring which processes call AI-related domains.
package sai

import (
	"github.com/knostic/sai/internal/capture"
	"github.com/knostic/sai/types"
)

// Monitor interface for network event capture
type Monitor interface {
	Start() error
	Stop()
	Events() <-chan types.Event
}

// NewMonitor creates a new network monitor with the given config
func NewMonitor(cfg Config) Monitor {
	if cfg.Interface == "" {
		cfg.Interface = "en0"
	}
	return capture.NewSNIMonitor(types.Config(cfg))
}
