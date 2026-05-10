// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMemoryPollInterval controls how often the memory collector
// re-reads /proc/meminfo. 1s is plenty — RSS doesn't move that fast.
const DefaultMemoryPollInterval = time.Second

// MemoryCollector polls /proc/meminfo on an interval and exposes a
// MemorySnapshot with current usage and a smoothed growth rate. It
// feeds the doctor's oom_imminent rule.
//
// Unlike the eBPF collectors, this one doesn't depend on root or BPF —
// it works on any Linux. /proc/meminfo is world-readable.
type MemoryCollector struct {
	logger   *slog.Logger
	interval time.Duration
	procPath string

	mu    sync.Mutex
	snap  MemorySnapshot
	prev  memSample
	have  bool
	start time.Time

	cancelFn context.CancelFunc
	done     chan struct{}
}

type memSample struct {
	used uint64
	at   time.Time
}

// NewMemoryCollector creates a memory collector polling /proc/meminfo
// every interval. interval ≤ 0 falls back to DefaultMemoryPollInterval.
func NewMemoryCollector(logger *slog.Logger, interval time.Duration) *MemoryCollector {
	if interval <= 0 {
		interval = DefaultMemoryPollInterval
	}
	return &MemoryCollector{
		logger:   logger.With("collector", "memory"),
		interval: interval,
		procPath: "/proc/meminfo",
		done:     make(chan struct{}),
	}
}

// Name implements Collector.
func (c *MemoryCollector) Name() string { return "memory" }

// Start implements Collector.
func (c *MemoryCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	c.start = time.Now()

	// Take an initial sample synchronously so Snapshot() returns
	// non-zero even if it's called before the first tick.
	if err := c.poll(); err != nil {
		c.logger.Warn("initial memory poll failed", "error", err)
	}

	go c.loop(runCtx)
	return nil
}

// Stop implements Collector.
func (c *MemoryCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("memory collector did not stop within timeout")
	}
}

func (c *MemoryCollector) loop(ctx context.Context) {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.poll(); err != nil {
				c.logger.Debug("memory poll failed", "error", err)
			}
		}
	}
}

// poll reads /proc/meminfo, computes used = total - available, and
// updates the snapshot. The growth rate is derived from the previous
// sample's used value over its time delta.
func (c *MemoryCollector) poll() error {
	f, err := os.Open(c.procPath)
	if err != nil {
		return fmt.Errorf("open meminfo: %w", err)
	}
	defer f.Close()

	var total, available, swapTotal, swapFree uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := parseMeminfoLine(line)
		if !ok {
			continue
		}
		switch key {
		case "MemTotal":
			total = val * 1024
		case "MemAvailable":
			available = val * 1024
		case "SwapTotal":
			swapTotal = val * 1024
		case "SwapFree":
			swapFree = val * 1024
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if total == 0 {
		return fmt.Errorf("MemTotal not found in %s", c.procPath)
	}

	used := total - available
	usedPct := float64(used) / float64(total) * 100.0
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	var growth float64
	if c.have {
		dt := now.Sub(c.prev.at).Seconds()
		if dt > 0 {
			growth = float64(int64(used)-int64(c.prev.used)) / dt
		}
	}

	c.snap = MemorySnapshot{
		TotalBytes:            total,
		UsedBytes:             used,
		UsedPct:               usedPct,
		GrowthRateBytesPerSec: growth,
		AvailableBytes:        available,
		SwapTotalBytes:        swapTotal,
		SwapUsedBytes:         swapTotal - swapFree,
	}
	c.prev = memSample{used: used, at: now}
	c.have = true
	return nil
}

// Snapshot implements Collector. Returns *MemorySnapshot.
func (c *MemoryCollector) Snapshot() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.have {
		return nil
	}
	out := c.snap
	return &out
}

// parseMeminfoLine returns (key, value-in-kB, ok) for a /proc/meminfo line.
// Lines look like "MemTotal:       16284980 kB".
func parseMeminfoLine(line string) (string, uint64, bool) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return "", 0, false
	}
	key := line[:colon]
	rest := strings.TrimSpace(line[colon+1:])
	rest = strings.TrimSuffix(rest, " kB")
	v, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
	if err != nil {
		return "", 0, false
	}
	return key, v, true
}
