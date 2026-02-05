// Package sai provides shadow AI detection by monitoring which processes call AI-related domains.
package sai

import "github.com/knostic/agentsonar/types"

// Monitor interface for network event capture
type Monitor interface {
	Start() error
	Stop()
	Events() <-chan types.Event
}
