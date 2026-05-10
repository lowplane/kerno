// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector/aggregator"
)

// DefaultSyscallKeyCap caps the number of unique (syscall, comm) keys
// tracked by a SyscallCollector. Beyond this, the LRU evicts the
// least-recently-seen key.
const DefaultSyscallKeyCap = 4096

// MaxSyscallEntriesPerSnapshot bounds the size of the SyscallSnapshot
// returned by Snapshot(), keeping report rendering fast even when
// thousands of (syscall, comm) keys are tracked.
const MaxSyscallEntriesPerSnapshot = 64

// SyscallCollector consumes syscall_latency eBPF events and aggregates
// them by (syscall_nr, comm) into a SyscallSnapshot.
type SyscallCollector struct {
	logger *slog.Logger
	loader *bpf.SyscallLatencyLoader
	cap    int

	mu         sync.Mutex
	keys       *aggregator.LRU[syscallKey, *syscallEntry]
	totalCount uint64

	cancelFn context.CancelFunc
	done     chan struct{}
}

type syscallKey struct {
	nr   uint32
	comm string
}

type syscallEntry struct {
	hist       *aggregator.Histogram
	count      uint64
	errorCount uint64
}

// NewSyscallCollector creates a collector that consumes events from
// loader.
func NewSyscallCollector(logger *slog.Logger, loader *bpf.SyscallLatencyLoader) *SyscallCollector {
	return NewSyscallCollectorWithCap(logger, loader, DefaultSyscallKeyCap)
}

// NewSyscallCollectorWithCap is like NewSyscallCollector but allows the
// per-(syscall, comm) tracking cap to be tuned.
func NewSyscallCollectorWithCap(logger *slog.Logger, loader *bpf.SyscallLatencyLoader, keyCap int) *SyscallCollector {
	return &SyscallCollector{
		logger: logger.With("collector", "syscall"),
		loader: loader,
		cap:    keyCap,
		keys:   aggregator.NewLRU[syscallKey, *syscallEntry](keyCap),
		done:   make(chan struct{}),
	}
}

// Name implements Collector.
func (c *SyscallCollector) Name() string { return "syscall" }

// Start implements Collector. It spawns a goroutine that decodes raw
// events from the loader's ring buffer until the context is canceled.
func (c *SyscallCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel

	ch, err := c.loader.Events(runCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("opening syscall events: %w", err)
	}

	go c.consume(runCtx, ch)
	return nil
}

// Stop implements Collector.
func (c *SyscallCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("collector did not stop within timeout")
	}
}

func (c *SyscallCollector) consume(ctx context.Context, ch <-chan bpf.RawEvent) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			event, err := bpf.DecodeSyscallEvent(raw.Data)
			if err != nil {
				c.logger.Debug("decode error", "error", err)
				continue
			}
			c.record(event)
		}
	}
}

func (c *SyscallCollector) record(event *bpf.SyscallEvent) {
	key := syscallKey{nr: event.SyscallNr, comm: event.CommString()}

	c.mu.Lock()
	entry, ok := c.keys.Get(key)
	if !ok {
		entry = &syscallEntry{hist: aggregator.New()}
		c.keys.Put(key, entry)
	}
	entry.hist.Record(event.LatencyNs)
	entry.count++
	if bpf.IsSyscallError(event.Ret) {
		entry.errorCount++
	}
	c.totalCount++
	c.mu.Unlock()
}

// Snapshot implements Collector. Returns *SyscallSnapshot.
func (c *SyscallCollector) Snapshot() any {
	c.mu.Lock()
	total := c.totalCount
	entries := make([]SyscallEntry, 0, c.keys.Len())
	c.keys.Range(func(k syscallKey, v *syscallEntry) bool {
		entries = append(entries, SyscallEntry{
			SyscallNr:  k.nr,
			Name:       bpf.SyscallName(k.nr),
			Comm:       k.comm,
			Count:      v.count,
			ErrorCount: v.errorCount,
			Latency:    histogramPercentiles(v.hist),
		})
		return true
	})
	c.mu.Unlock()

	// Rank by p99 desc so the report shows worst offenders first.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Latency.P99 != entries[j].Latency.P99 {
			return entries[i].Latency.P99 > entries[j].Latency.P99
		}
		return entries[i].Count > entries[j].Count
	})

	if len(entries) > MaxSyscallEntriesPerSnapshot {
		entries = entries[:MaxSyscallEntriesPerSnapshot]
	}

	return &SyscallSnapshot{
		Entries:    entries,
		TotalCount: total,
	}
}

// histogramPercentiles converts an aggregator.Histogram into the
// collector.Percentiles type used by snapshots.
func histogramPercentiles(h *aggregator.Histogram) Percentiles {
	return Percentiles{
		P50: time.Duration(h.Percentile(50)),
		P95: time.Duration(h.Percentile(95)),
		P99: time.Duration(h.Percentile(99)),
		Max: time.Duration(h.Max()),
	}
}
