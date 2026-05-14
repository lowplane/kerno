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
	DefaultSchedKeyCap         = 4096
	MaxSchedEntriesPerSnapshot = 16
)

// SchedCollector consumes sched_delay eBPF events and aggregates run
// queue delay distributions globally and per-process into a
// SchedSnapshot.
type SchedCollector struct {
	logger *slog.Logger
	loader *bpf.SchedDelayLoader
	cap    int

	mu     sync.Mutex
	global *aggregator.Histogram
	keys   *aggregator.LRU[schedKey, *schedEntry]
	total  uint64

	cancelFn context.CancelFunc
	done     chan struct{}
}

type schedKey struct {
	pid  uint32
	comm string
}

type schedEntry struct {
	hist  *aggregator.Histogram
	count uint64
}

// NewSchedCollector creates a sched-delay collector with default capacity.
func NewSchedCollector(logger *slog.Logger, loader *bpf.SchedDelayLoader) *SchedCollector {
	return NewSchedCollectorWithCap(logger, loader, DefaultSchedKeyCap)
}

// NewSchedCollectorWithCap allows tuning the per-(pid, comm) cap.
func NewSchedCollectorWithCap(logger *slog.Logger, loader *bpf.SchedDelayLoader, keyCap int) *SchedCollector {
	return &SchedCollector{
		logger: logger.With("collector", "sched"),
		loader: loader,
		cap:    keyCap,
		global: aggregator.New(),
		keys:   aggregator.NewLRU[schedKey, *schedEntry](keyCap),
		done:   make(chan struct{}),
	}
}

// Name implements Collector.
func (c *SchedCollector) Name() string { return "sched" }

// Start implements Collector.
func (c *SchedCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel

	ch, err := c.loader.Events(runCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("opening sched events: %w", err)
	}

	go c.consume(runCtx, ch)
	return nil
}

// Stop implements Collector.
func (c *SchedCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("collector did not stop within timeout")
	}
}

func (c *SchedCollector) consume(ctx context.Context, ch <-chan bpf.RawEvent) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			event, err := bpf.DecodeSchedEvent(raw.Data)
			if err != nil {
				c.logger.Debug("decode error", "error", err)
				continue
			}
			c.record(event)
		}
	}
}

func (c *SchedCollector) record(event *bpf.SchedEvent) {
	key := schedKey{pid: event.PID, comm: event.CommString()}

	c.mu.Lock()
	c.global.Record(event.RunqDelayNs)
	entry, ok := c.keys.Get(key)
	if !ok {
		entry = &schedEntry{hist: aggregator.New()}
		c.keys.Put(key, entry)
	}
	entry.hist.Record(event.RunqDelayNs)
	entry.count++
	c.total++
	c.mu.Unlock()
}

// Snapshot implements Collector. Returns *SchedSnapshot.
func (c *SchedCollector) Snapshot() any {
	c.mu.Lock()
	total := c.total
	globalSnap := c.global.Snapshot()
	type kv struct {
		k schedKey
		v *schedEntry
	}
	all := make([]kv, 0, c.keys.Len())
	c.keys.Range(func(k schedKey, v *schedEntry) bool {
		all = append(all, kv{k, v})
		return true
	})
	c.mu.Unlock()

	// Rank by p99 delay desc.
	sort.Slice(all, func(i, j int) bool {
		return all[i].v.hist.Percentile(99) > all[j].v.hist.Percentile(99)
	})

	limit := MaxSchedEntriesPerSnapshot
	if len(all) < limit {
		limit = len(all)
	}
	top := make([]SchedEntry, 0, limit)
	for _, e := range all[:limit] {
		top = append(top, SchedEntry{
			PID:       e.k.pid,
			Comm:      e.k.comm,
			Count:     e.v.count,
			RunqDelay: histogramPercentiles(e.v.hist),
		})
	}

	return &SchedSnapshot{
		RunqDelay: Percentiles{
			P50: time.Duration(globalSnap.Percentile(50)),
			P95: time.Duration(globalSnap.Percentile(95)),
			P99: time.Duration(globalSnap.Percentile(99)),
			Max: time.Duration(globalSnap.Max()),
		},
		TopDelayed: top,
		TotalCount: total,
	}
}
