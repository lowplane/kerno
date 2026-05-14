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
)

// MaxOOMEvents caps the per-window OOM event log so a runaway OOMing
// process can't drive unbounded memory growth.
const MaxOOMEvents = 256

// OOMCollector consumes oom_track eBPF events and stores each one as a
// discrete OOMEventEntry in an OOMSnapshot. OOM events are not
// aggregated — every kill is critical and reported individually.
type OOMCollector struct {
	logger *slog.Logger
	loader *bpf.OOMTrackLoader

	mu     sync.Mutex
	events []OOMEventEntry

	cancelFn context.CancelFunc
	done     chan struct{}
}

// NewOOMCollector creates an OOM collector.
func NewOOMCollector(logger *slog.Logger, loader *bpf.OOMTrackLoader) *OOMCollector {
	return &OOMCollector{
		logger: logger.With("collector", "oom"),
		loader: loader,
		done:   make(chan struct{}),
	}
}

// Name implements Collector.
func (c *OOMCollector) Name() string { return "oom" }

// Start implements Collector.
func (c *OOMCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel

	ch, err := c.loader.Events(runCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("opening oom events: %w", err)
	}

	go c.consume(runCtx, ch)
	return nil
}

// Stop implements Collector.
func (c *OOMCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("collector did not stop within timeout")
	}
}

func (c *OOMCollector) consume(ctx context.Context, ch <-chan bpf.RawEvent) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			event, err := bpf.DecodeOOMEvent(raw.Data)
			if err != nil {
				c.logger.Debug("decode error", "error", err)
				continue
			}
			c.record(event)
		}
	}
}

func (c *OOMCollector) record(event *bpf.OOMEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.events) >= MaxOOMEvents {
		// Drop oldest, keep newest. OOMing in a tight loop is itself
		// signal — the doctor still flags any non-zero count.
		c.events = c.events[1:]
	}

	c.events = append(c.events, OOMEventEntry{
		Timestamp:    time.Unix(0, int64(event.TimestampNs)),
		PID:          event.PID,
		Comm:         event.CommString(),
		TriggeredPID: event.TriggeredPID,
		TotalPages:   event.TotalPages,
		RSSPages:     event.RSSPages,
		OOMScore:     event.OOMScore,
		CgroupID:     event.CgroupID,
	})
}

// Snapshot implements Collector. Returns *OOMSnapshot.
func (c *OOMCollector) Snapshot() any {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := &OOMSnapshot{
		Events: make([]OOMEventEntry, len(c.events)),
		Count:  len(c.events),
	}
	copy(out.Events, c.events)
	return out
}
