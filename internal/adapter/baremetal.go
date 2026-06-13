// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"log/slog"
	"os"
	"strings"
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

// DetectCloud tries to determine the cloud provider and instance type
// by reading DMI sysfs files.
func DetectCloud() (provider, instanceType string) {
	if vendorBytes, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.TrimSpace(string(vendorBytes))
		switch {
		case strings.Contains(vendor, "Amazon EC2"):
			provider = "AWS EC2"
		case strings.Contains(vendor, "Google"):
			provider = "Google Cloud"
		case strings.Contains(vendor, "Microsoft Corporation"):
			provider = "Azure"
		}
	}

	if productBytes, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.TrimSpace(string(productBytes))
		if product != "" {
			instanceType = product
		}
	}

	return provider, instanceType
}

