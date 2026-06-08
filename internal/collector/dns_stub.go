// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !ebpf

package collector

import (
"context"
"log/slog"
)

// DNSCollector is a no-op stub when eBPF is not compiled in.
// The real implementation lives in dns.go (build tag: ebpf).
type DNSCollector struct{}

// NewDNSCollector returns a no-op collector.
func NewDNSCollector(logger *slog.Logger, loader any) *DNSCollector {
return &DNSCollector{}
}

func (c *DNSCollector) Name() string           { return "dns" }
func (c *DNSCollector) Start(_ context.Context) error { return nil }
func (c *DNSCollector) Stop()                  {}
func (c *DNSCollector) Snapshot() any          { return (*DNSSnapshot)(nil) }