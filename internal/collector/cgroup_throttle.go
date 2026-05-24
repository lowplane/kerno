// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package collector provides CgroupThrottleCollector which polls
// /sys/fs/cgroup/<path>/cpu.stat for every container cgroup every 5s,
// computes per-interval deltas, and exposes per-container CPU throttle
// statistics to the doctor engine.
package collector

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/optiqor/kerno/internal/metrics"
)

const DefaultCgroupThrottlePollInterval = 5 * time.Second
const maxThrottleWalkDepth = 8

type CPUThrottleSnapshot struct {
	Containers []CPUThrottleEntry
}

type CPUThrottleEntry struct {
	CgroupPath  string
	Pod         string
	Namespace   string
	Container   string
	NrThrottled uint64
	NrPeriods   uint64
	ThrottlePct float64
	ThrottledNs uint64
}

type cpuStatSample struct {
	nrPeriods   uint64
	nrThrottled uint64
	throttledUs uint64
	at          time.Time
}

type CgroupThrottleCollector struct {
	logger     *slog.Logger
	interval   time.Duration
	cgroupRoot string
	mu         sync.Mutex
	snap       *CPUThrottleSnapshot
	prev       map[string]cpuStatSample
	cancelFn   context.CancelFunc
	done       chan struct{}
}

func NewCgroupThrottleCollector(logger *slog.Logger, interval time.Duration) *CgroupThrottleCollector {
	if interval <= 0 {
		interval = DefaultCgroupThrottlePollInterval
	}
	root := "/sys/fs/cgroup"
	if env := os.Getenv("KERNO_CGROUP_ROOT"); env != "" {
		root = env
	}
	return &CgroupThrottleCollector{
		logger:     logger.With("collector", "cgroup_throttle"),
		interval:   interval,
		cgroupRoot: root,
		prev:       make(map[string]cpuStatSample),
		done:       make(chan struct{}),
	}
}

func (c *CgroupThrottleCollector) Name() string { return "cgroup_throttle" }

func (c *CgroupThrottleCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	if err := c.poll(); err != nil {
		c.logger.Debug("initial cgroup throttle poll failed", "error", err)
	}
	go c.loop(runCtx)
	return nil
}

func (c *CgroupThrottleCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("cgroup throttle collector did not stop within timeout")
	}
}

func (c *CgroupThrottleCollector) loop(ctx context.Context) {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.poll(); err != nil {
				c.logger.Debug("cgroup throttle poll failed", "error", err)
			}
		}
	}
}

func (c *CgroupThrottleCollector) poll() error {
	entries, err := c.walkCgroups(c.cgroupRoot, 0)
	if err != nil {
		return fmt.Errorf("cgroup throttle walk: %w", err)
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range entries {
		prev, ok := c.prev[entries[i].CgroupPath]
		if ok && now.Sub(prev.at).Seconds() > 0 {
			dNr := diffUint64(entries[i].NrPeriods, prev.nrPeriods)
			dTh := diffUint64(entries[i].NrThrottled, prev.nrThrottled)
			dUs := diffUint64(entries[i].ThrottledNs/1000, prev.throttledUs)
			entries[i].NrPeriods = dNr
			entries[i].NrThrottled = dTh
			entries[i].ThrottledNs = dUs * 1000
			if dNr > 0 {
				entries[i].ThrottlePct = float64(dTh) / float64(dNr) * 100.0
			}
		}
		raw := readCPUStat(filepath.Join(entries[i].CgroupPath, "cpu.stat"))
		c.prev[entries[i].CgroupPath] = cpuStatSample{
			nrPeriods:   raw["nr_periods"],
			nrThrottled: raw["nr_throttled"],
			throttledUs: raw["throttled_usec"],
			at:          now,
		}
	}

	var limited []CPUThrottleEntry
	for _, e := range entries {
		if e.NrPeriods > 0 {
			limited = append(limited, e)
		}
	}
	if len(limited) == 0 {
		c.snap = nil
		metrics.CgroupCPUThrottledPct.Reset()
		return nil
	}
	c.snap = &CPUThrottleSnapshot{Containers: limited}
	metrics.CgroupCPUThrottledPct.Reset()
	for _, e := range limited {
		metrics.CgroupCPUThrottledPct.WithLabelValues(e.Pod, e.Namespace).Set(e.ThrottlePct)
	}
	return nil
}

func (c *CgroupThrottleCollector) Snapshot() interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap == nil {
		return nil
	}
	out := *c.snap
	return &out
}

func (c *CgroupThrottleCollector) walkCgroups(dir string, depth int) ([]CPUThrottleEntry, error) {
	if depth > maxThrottleWalkDepth {
		return nil, nil
	}
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil
		}
		return nil, err
	}
	raw := readCPUStat(filepath.Join(dir, "cpu.stat"))
	nrPeriods := raw["nr_periods"]
	nrThrottled := raw["nr_throttled"]
	throttledUs := raw["throttled_usec"]

	var result []CPUThrottleEntry
	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}
		sub := filepath.Join(dir, de.Name())
		children, err := c.walkCgroups(sub, depth+1)
		if err != nil {
			c.logger.Debug("cgroup throttle walk error", "path", sub, "error", err)
			continue
		}
		result = append(result, children...)
	}
	if nrPeriods > 0 && len(result) == 0 {
		pod := parseCgroupPod(dir)
		result = append(result, CPUThrottleEntry{
			CgroupPath:  dir,
			Pod:         pod,
			Namespace:   "",
			Container:   filepath.Base(dir),
			NrPeriods:   nrPeriods,
			NrThrottled: nrThrottled,
			ThrottledNs: throttledUs * 1000,
			ThrottlePct: throttlePct(nrThrottled, nrPeriods),
		})
	}
	return result, nil
}

func readCPUStat(path string) map[string]uint64 {
	out := make(map[string]uint64)
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 2 {
			continue
		}
		v, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		out[parts[0]] = v
	}
	return out
}

func throttlePct(nrThrottled, nrPeriods uint64) float64 {
	if nrPeriods == 0 {
		return 0
	}
	return float64(nrThrottled) / float64(nrPeriods) * 100.0
}

func diffUint64(current, prev uint64) uint64 {
	if current >= prev {
		return current - prev
	}
	return current
}
