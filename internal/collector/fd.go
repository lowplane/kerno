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

const (
	DefaultFDKeyCap         = 4096
	MaxFDEntriesPerSnapshot = 16
)

// FDCollector consumes fd_track eBPF events and computes per-process
// open/close counters and growth rate to detect file descriptor leaks.
type FDCollector struct {
	logger *slog.Logger
	loader *bpf.FDTrackLoader
	cap    int

	mu          sync.Mutex
	keys        *aggregator.LRU[fdKey, *fdEntry]
	totalOpens  uint64
	totalCloses uint64
	startTime   time.Time

	cancelFn context.CancelFunc
	done     chan struct{}
}

type fdKey struct {
	pid  uint32
	comm string
}

type fdEntry struct {
	opens     uint64
	closes    uint64
	firstSeen time.Time
}

// NewFDCollector creates an FD-tracking collector.
func NewFDCollector(logger *slog.Logger, loader *bpf.FDTrackLoader) *FDCollector {
	return NewFDCollectorWithCap(logger, loader, DefaultFDKeyCap)
}

// NewFDCollectorWithCap allows tuning the per-(pid, comm) cap.
func NewFDCollectorWithCap(logger *slog.Logger, loader *bpf.FDTrackLoader, keyCap int) *FDCollector {
	return &FDCollector{
		logger: logger.With("collector", "fd"),
		loader: loader,
		cap:    keyCap,
		keys:   aggregator.NewLRU[fdKey, *fdEntry](keyCap),
		done:   make(chan struct{}),
	}
}

// Name implements Collector.
func (c *FDCollector) Name() string { return "fd" }

// Start implements Collector.
func (c *FDCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	c.startTime = time.Now()

	ch, err := c.loader.Events(runCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("opening fd events: %w", err)
	}

	go c.consume(runCtx, ch)
	return nil
}

// Stop implements Collector.
func (c *FDCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("collector did not stop within timeout")
	}
}

func (c *FDCollector) consume(ctx context.Context, ch <-chan bpf.RawEvent) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			event, err := bpf.DecodeFDEvent(raw.Data)
			if err != nil {
				c.logger.Debug("decode error", "error", err)
				continue
			}
			c.record(event)
		}
	}
}

func (c *FDCollector) record(event *bpf.FDEvent) {
	key := fdKey{pid: event.PID, comm: event.CommString()}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.keys.Get(key)
	if !ok {
		entry = &fdEntry{firstSeen: time.Now()}
		c.keys.Put(key, entry)
	}

	switch event.Op {
	case bpf.FDOpOpen:
		entry.opens++
		c.totalOpens++
	case bpf.FDOpClose:
		entry.closes++
		c.totalCloses++
	}
}

// Snapshot implements Collector. Returns *FDSnapshot.
func (c *FDCollector) Snapshot() any {
	c.mu.Lock()
	totalOpens := c.totalOpens
	totalCloses := c.totalCloses
	startTime := c.startTime
	type kv struct {
		k fdKey
		v *fdEntry
	}
	all := make([]kv, 0, c.keys.Len())
	c.keys.Range(func(k fdKey, v *fdEntry) bool {
		all = append(all, kv{k, v})
		return true
	})
	c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(startTime).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	netDelta := int64(totalOpens) - int64(totalCloses)
	growthRate := float64(netDelta) / elapsed

	entries := make([]FDEntry, 0, len(all))
	for _, e := range all {
		entryDelta := int64(e.v.opens) - int64(e.v.closes)
		entryElapsed := now.Sub(e.v.firstSeen).Seconds()
		if entryElapsed <= 0 {
			entryElapsed = 1
		}
		entries = append(entries, FDEntry{
			PID:        e.k.pid,
			Comm:       e.k.comm,
			Opens:      e.v.opens,
			Closes:     e.v.closes,
			NetDelta:   entryDelta,
			GrowthRate: float64(entryDelta) / entryElapsed,
		})
	}

	// Rank by net delta desc (likely leakers first).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].NetDelta > entries[j].NetDelta
	})
	if len(entries) > MaxFDEntriesPerSnapshot {
		entries = entries[:MaxFDEntriesPerSnapshot]
	}

	// Populate CurrentFDs and FDLimit for the top-N entries (capped to avoid
	// /proc overhead on systems with thousands of processes).
	const procReadCap = 5
	for i := range entries {
		if i >= procReadCap {
			break
		}
		if n, err := CountProcFDs(entries[i].PID); err == nil {
			entries[i].CurrentFDs = n
		}
		if lim, err := ReadProcFDLimit(entries[i].PID); err == nil && lim > 0 {
			entries[i].FDLimit = lim
		}
	}

	topCurrentFDs := 0
	if len(entries) > 0 {
		topCurrentFDs = entries[0].CurrentFDs
	}

	return &FDSnapshot{
		Entries:          entries,
		TotalOpens:       totalOpens,
		TotalCloses:      totalCloses,
		NetDelta:         netDelta,
		GrowthRate:       growthRate,
		TopPIDCurrentFDs: topCurrentFDs,
	}
}
