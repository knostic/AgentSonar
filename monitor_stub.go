//go:build !darwin && !linux

package sai

import (
	"fmt"

	"github.com/knostic/sai/types"
)

func NewMonitor(cfg Config) Monitor {
	return &stubMonitor{}
}

type stubMonitor struct {
	ch chan types.Event
}

func (m *stubMonitor) Start() error {
	return fmt.Errorf("network monitoring requires darwin or linux")
}

func (m *stubMonitor) Stop() {}

func (m *stubMonitor) Events() <-chan types.Event {
	if m.ch == nil {
		m.ch = make(chan types.Event)
		close(m.ch)
	}
	return m.ch
}
