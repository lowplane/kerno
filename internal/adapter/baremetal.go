// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"log/slog"
	"os"
)

// BareMetalAdapter enriches events with basic host metadata.
// This is the fallback adapter that always works.
type BareMetalAdapter struct {
	logger   *slog.Logger
	hostname string
}

// NewBareMetalAdapter creates a bare metal adapter.
func NewBareMetalAdapter(logger *slog.Logger) *BareMetalAdapter {
	hostname, _ := os.Hostname()
	return &BareMetalAdapter{
		logger:   logger,
		hostname: hostname,
	}
}

func (a *BareMetalAdapter) Name() string { return "baremetal" }

func (a *BareMetalAdapter) Start(_ context.Context) error {
	a.logger.Info("bare metal adapter started", "hostname", a.hostname)
	return nil
}

func (a *BareMetalAdapter) Stop() {}

// Enrich adds hostname and cgroup path to the event metadata.
func (a *BareMetalAdapter) Enrich(meta *EventMeta) {
	meta.Hostname = a.hostname
	if meta.PID > 0 && meta.CgroupPath == "" {
		meta.CgroupPath = cgroupPathForPID(meta.PID)
	}
}
