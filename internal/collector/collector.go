// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// Package collector defines the interface and registry for signal collectors.
//
// Each collector consumes raw eBPF events from a BPF loader, enriches and
// aggregates them into typed signal snapshots, and exposes them for
// consumption by the doctor engine, exporters, and dashboard.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Collector reads raw eBPF events, aggregates them, and produces typed
// signal snapshots over configurable time windows.
type Collector interface {
	// Name returns the collector identifier (e.g., "syscall", "tcp").
	Name() string

	// Start begins consuming events from the eBPF ring buffer.
	// The collector runs until the context is canceled.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the collector, flushing any buffered events.
	Stop()

	// Snapshot returns a point-in-time copy of the aggregated signals.
	// The returned value is safe for concurrent read by other goroutines.
	Snapshot() interface{}
}

// Registry manages the lifecycle of multiple collectors.
// It provides fan-in of signals from all active collectors into a
// combined Signals snapshot.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]Collector
	logger     *slog.Logger
}

// NewRegistry creates a new collector registry.
func NewRegistry(logger *slog.Logger) *Registry {
	return &Registry{
		collectors: make(map[string]Collector),
		logger:     logger,
	}
}

// Register adds a collector to the registry.
// Returns an error if a collector with the same name is already registered.
func (r *Registry) Register(c Collector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.collectors[c.Name()]; exists {
		return fmt.Errorf("collector %q already registered", c.Name())
	}

	r.collectors[c.Name()] = c
	r.logger.Info("registered collector", "name", c.Name())
	return nil
}

// StartAll starts all registered collectors.
// Returns the first error encountered; collectors that started successfully
// remain running and should be stopped with StopAll.
func (r *Registry) StartAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, c := range r.collectors {
		r.logger.Info("starting collector", "name", name)
		if err := c.Start(ctx); err != nil {
			return fmt.Errorf("starting collector %q: %w", name, err)
		}
	}
	return nil
}

// StopAll gracefully stops all registered collectors.
func (r *Registry) StopAll() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, c := range r.collectors {
		r.logger.Info("stopping collector", "name", name)
		c.Stop()
	}
}

// Get returns a collector by name, or nil if not found.
func (r *Registry) Get(name string) Collector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.collectors[name]
}

// Names returns the names of all registered collectors.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.collectors))
	for name := range r.collectors {
		names = append(names, name)
	}
	return names
}

// Signals collects snapshots from all collectors into a combined Signals struct.
func (r *Registry) Signals(duration time.Duration) *Signals {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s := &Signals{
		Timestamp: time.Now(),
		Duration:  duration,
	}

	for _, c := range r.collectors {
		snap := c.Snapshot()
		if snap == nil {
			continue
		}
		switch v := snap.(type) {
		case *SyscallSnapshot:
			s.Syscall = v
		case *TCPSnapshot:
			s.TCP = v
		case *OOMSnapshot:
			s.OOM = v
		case *DiskIOSnapshot:
			s.DiskIO = v
		case *SchedSnapshot:
			s.Sched = v
		case *FDSnapshot:
			s.FD = v
		}
	}

	return s
}
