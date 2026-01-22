// Package sai provides shadow AI detection by monitoring which processes call AI-related domains.
package sai

// Config configures the monitor
type Config struct {
	Interface  string // network interface (default: en0)
	EnablePID0 bool   // include PID 0 / system processes
}

// Monitor interface for network event capture
type Monitor interface {
	Start() error
	Stop()
	Events() <-chan Event
}

// NewMonitor creates a new network monitor with the given config
func NewMonitor(cfg Config) Monitor {
	if cfg.Interface == "" {
		cfg.Interface = "en0"
	}
	return newSNIMonitor(cfg)
}
