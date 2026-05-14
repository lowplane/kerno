// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// SystemdAdapter enriches events with systemd unit metadata by
// parsing the cgroup v2 path. On systemd-managed hosts, processes
// are organized into slices, scopes, and services.
//
// Example cgroup paths:
//
//	/system.slice/nginx.service
//	/user.slice/user-1000.slice/session-2.scope
//	/system.slice/docker-abc123.scope
type SystemdAdapter struct {
	logger   *slog.Logger
	hostname string
}

// NewSystemdAdapter creates a systemd adapter.
func NewSystemdAdapter(logger *slog.Logger) *SystemdAdapter {
	hostname, _ := os.Hostname()
	return &SystemdAdapter{
		logger:   logger,
		hostname: hostname,
	}
}

func (a *SystemdAdapter) Name() string { return "systemd" }

func (a *SystemdAdapter) Start(_ context.Context) error {
	a.logger.Info("systemd adapter started", "hostname", a.hostname)
	return nil
}

func (a *SystemdAdapter) Stop() {}

// Enrich parses the cgroup path to extract systemd unit, slice, and scope.
func (a *SystemdAdapter) Enrich(meta *EventMeta) {
	meta.Hostname = a.hostname

	if meta.PID > 0 && meta.CgroupPath == "" {
		meta.CgroupPath = cgroupPathForPID(meta.PID)
	}

	if meta.CgroupPath == "" {
		return
	}

	unit, slice, scope := parseSystemdCgroup(meta.CgroupPath)
	meta.Unit = unit
	meta.Slice = slice
	meta.Scope = scope
}

// parseSystemdCgroup extracts unit, slice, and scope from a cgroup path.
//
// The cgroup path under systemd follows the pattern:
//
//	/<slice>/<unit-or-scope>
//
// Examples:
//
//	/system.slice/nginx.service → unit=nginx.service, slice=system.slice
//	/user.slice/user-1000.slice/session-2.scope → scope=session-2.scope, slice=user.slice/user-1000.slice
//	/system.slice/docker-abc.scope → scope=docker-abc.scope, slice=system.slice
func parseSystemdCgroup(path string) (unit, slice, scope string) {
	// Remove leading slash.
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return
	}

	parts := strings.Split(path, "/")

	// Walk parts to find slices, services, and scopes.
	var sliceParts []string
	for _, p := range parts {
		switch {
		case strings.HasSuffix(p, ".service"):
			unit = p
		case strings.HasSuffix(p, ".scope"):
			scope = p
		case strings.HasSuffix(p, ".slice"):
			sliceParts = append(sliceParts, p)
		}
	}

	if len(sliceParts) > 0 {
		slice = strings.Join(sliceParts, "/")
	}

	return unit, slice, scope
}
