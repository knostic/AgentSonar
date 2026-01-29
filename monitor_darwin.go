//go:build darwin

package sai

import (
	"github.com/knostic/sai/internal/capture"
	"github.com/knostic/sai/types"
)

func NewMonitor(cfg Config) Monitor {
	if cfg.Interface == "" {
		cfg.Interface = "en0"
	}
	return &monitorWrapper{inner: capture.NewSNIMonitor(types.Config(cfg))}
}

type monitorWrapper struct {
	inner Monitor
}

func (m *monitorWrapper) Start() error {
	err := m.inner.Start()
	if err != nil {
		if permErr := wrapPermissionError(err); permErr != nil {
			return permErr
		}
		return err
	}
	return nil
}

func (m *monitorWrapper) Stop() {
	m.inner.Stop()
}

func (m *monitorWrapper) Events() <-chan types.Event {
	return m.inner.Events()
}
