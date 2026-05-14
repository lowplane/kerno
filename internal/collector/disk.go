// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector/aggregator"
)

// DiskIOCollector consumes disk_io eBPF events and aggregates per-op
// latency distributions and throughput counts into a DiskIOSnapshot.
type DiskIOCollector struct {
	logger *slog.Logger
	loader *bpf.DiskIOLoader

	mu        sync.Mutex
	readHist  *aggregator.Histogram
	writeHist *aggregator.Histogram
	syncHist  *aggregator.Histogram
	reads     uint64
	writes    uint64
	syncs     uint64
	rdBytes   uint64
	wrBytes   uint64

	cancelFn context.CancelFunc
	done     chan struct{}
}

// NewDiskIOCollector creates a disk I/O collector.
func NewDiskIOCollector(logger *slog.Logger, loader *bpf.DiskIOLoader) *DiskIOCollector {
	return &DiskIOCollector{
		logger:    logger.With("collector", "diskio"),
		loader:    loader,
		readHist:  aggregator.New(),
		writeHist: aggregator.New(),
		syncHist:  aggregator.New(),
		done:      make(chan struct{}),
	}
}

// Name implements Collector.
func (c *DiskIOCollector) Name() string { return "diskio" }

// Start implements Collector.
func (c *DiskIOCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel

	ch, err := c.loader.Events(runCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("opening disk events: %w", err)
	}

	go c.consume(runCtx, ch)
	return nil
}

// Stop implements Collector.
func (c *DiskIOCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("collector did not stop within timeout")
	}
}

func (c *DiskIOCollector) consume(ctx context.Context, ch <-chan bpf.RawEvent) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			event, err := bpf.DecodeDiskEvent(raw.Data)
			if err != nil {
				c.logger.Debug("decode error", "error", err)
				continue
			}
			c.record(event)
		}
	}
}

func (c *DiskIOCollector) record(event *bpf.DiskEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch event.Op {
	case 'R':
		c.readHist.Record(event.LatencyNs)
		c.reads++
		c.rdBytes += uint64(event.NrBytes)
	case 'W':
		c.writeHist.Record(event.LatencyNs)
		c.writes++
		c.wrBytes += uint64(event.NrBytes)
	case 'S':
		c.syncHist.Record(event.LatencyNs)
		c.syncs++
	}
}

// Snapshot implements Collector. Returns *DiskIOSnapshot.
func (c *DiskIOCollector) Snapshot() any {
	c.mu.Lock()
	defer c.mu.Unlock()

	return &DiskIOSnapshot{
		ReadLatency:  histogramPercentiles(c.readHist),
		WriteLatency: histogramPercentiles(c.writeHist),
		SyncLatency:  histogramPercentiles(c.syncHist),
		TotalReads:   c.reads,
		TotalWrites:  c.writes,
		TotalSyncs:   c.syncs,
		ReadBytes:    c.rdBytes,
		WriteBytes:   c.wrBytes,
	}
}
