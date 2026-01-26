//go:build linux

package sai

import (
	"github.com/knostic/sai/internal/capture"
	"github.com/knostic/sai/types"
)

func NewMonitor(cfg Config) Monitor {
	if cfg.Interface == "" {
		cfg.Interface = "eth0"
	}
	return capture.NewSNIMonitor(types.Config(cfg))
}
