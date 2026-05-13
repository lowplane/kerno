// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

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
)

// DefaultCgroupMemoryPollInterval is the polling cadence for cgroup memory
// files. 5s is enough resolution for OOMKill prediction while keeping
// /sys/fs/cgroup read overhead negligible.
const DefaultCgroupMemoryPollInterval = 5 * time.Second

// maxCgroupWalkDepth guards against unexpectedly deep cgroup trees.
const maxCgroupWalkDepth = 8

// CgroupMemoryCollector walks the cgroup v2 hierarchy and collects per-
// container memory state every poll interval. It feeds the doctor's
// memory_limit_pressure and memory_high_throttling rules.
//
// On bare metal without cgroup memory limits, Snapshot() returns nil —
// the rules gracefully handle the nil case.
type CgroupMemoryCollector struct {
	logger     *slog.Logger
	interval   time.Duration
	cgroupRoot string // overrideable for tests

	mu   sync.Mutex
	snap *CgroupMemorySnapshot
	prev map[string]cgroupMemSample

	cancelFn context.CancelFunc
	done     chan struct{}
}

type cgroupMemSample struct {
	currentBytes uint64
	eventsHigh   uint64
	at           time.Time
}

// NewCgroupMemoryCollector creates a collector that reads
// /sys/fs/cgroup (or cgroupRoot if overridden) every interval.
func NewCgroupMemoryCollector(logger *slog.Logger, interval time.Duration) *CgroupMemoryCollector {
	if interval <= 0 {
		interval = DefaultCgroupMemoryPollInterval
	}
	return &CgroupMemoryCollector{
		logger:     logger.With("collector", "cgroup_memory"),
		interval:   interval,
		cgroupRoot: "/sys/fs/cgroup",
		prev:       make(map[string]cgroupMemSample),
		done:       make(chan struct{}),
	}
}

// Name implements Collector.
func (c *CgroupMemoryCollector) Name() string { return "cgroup_memory" }

// Start implements Collector.
func (c *CgroupMemoryCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	if err := c.poll(); err != nil {
		c.logger.Debug("initial cgroup memory poll failed", "error", err)
	}
	go c.loop(runCtx)
	return nil
}

// Stop implements Collector.
func (c *CgroupMemoryCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("cgroup memory collector did not stop within timeout")
	}
}

func (c *CgroupMemoryCollector) loop(ctx context.Context) {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.poll(); err != nil {
				c.logger.Debug("cgroup memory poll failed", "error", err)
			}
		}
	}
}

func (c *CgroupMemoryCollector) poll() error {
	entries, err := c.walkCgroups(c.cgroupRoot, 0)
	if err != nil {
		return fmt.Errorf("cgroup walk: %w", err)
	}

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range entries {
		prev, ok := c.prev[entries[i].CgroupPath]
		if ok {
			dt := now.Sub(prev.at).Seconds()
			if dt > 0 {
				entries[i].GrowthRateBytesPerSec = float64(int64(entries[i].CurrentBytes)-int64(prev.currentBytes)) / dt
				rate := float64(int64(entries[i].EventsHigh)-int64(prev.eventsHigh)) / dt
				if rate > 0 {
					entries[i].HighEventRate = rate
				}
			}
		}
		c.prev[entries[i].CgroupPath] = cgroupMemSample{
			currentBytes: entries[i].CurrentBytes,
			eventsHigh:   entries[i].EventsHigh,
			at:           now,
		}
	}

	if len(entries) > 0 {
		c.snap = &CgroupMemorySnapshot{Containers: entries}
	}
	return nil
}

// Snapshot implements Collector. Returns *CgroupMemorySnapshot or nil.
func (c *CgroupMemoryCollector) Snapshot() interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap == nil {
		return nil
	}
	out := *c.snap
	return &out
}

// walkCgroups recursively visits cgroup directories and collects entries
// that have a finite memory.max limit (i.e., the value is not "max").
func (c *CgroupMemoryCollector) walkCgroups(dir string, depth int) ([]CgroupMemoryEntry, error) {
	if depth > maxCgroupWalkDepth {
		return nil, nil
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []CgroupMemoryEntry

	limitBytes, hasLimit := readCgroupMemoryMax(filepath.Join(dir, "memory.max"))
	if hasLimit {
		current := readCgroupUint64File(filepath.Join(dir, "memory.current"))
		highBytes := readCgroupUint64File(filepath.Join(dir, "memory.high"))
		events := readCgroupMemoryEvents(filepath.Join(dir, "memory.events"))

		usedPct := 0.0
		if limitBytes > 0 {
			usedPct = float64(current) / float64(limitBytes) * 100.0
		}

		pod := parseCgroupPod(dir)
		result = append(result, CgroupMemoryEntry{
			CgroupPath:    dir,
			Pod:           pod,
			Namespace:     "",
			CurrentBytes:  current,
			LimitBytes:    limitBytes,
			HighBytes:     highBytes,
			UsedPct:       usedPct,
			EventsHigh:    events["high"],
			EventsMax:     events["max"],
			EventsOOM:     events["oom"],
			EventsOOMKill: events["oom_kill"],
		})
	}

	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}
		sub := filepath.Join(dir, de.Name())
		children, err := c.walkCgroups(sub, depth+1)
		if err != nil {
			c.logger.Debug("cgroup walk error", "path", sub, "error", err)
			continue
		}
		result = append(result, children...)
	}

	return result, nil
}

// readCgroupMemoryMax reads memory.max. Returns (bytes, true) when a finite
// limit is set; (0, false) for "max" (unlimited) or missing file.
func readCgroupMemoryMax(path string) (uint64, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from the controlled cgroupRoot
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "max" || s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readCgroupUint64File reads a single uint64 from a cgroup file, returning 0
// on error or when the value is the sentinel "max".
func readCgroupUint64File(path string) uint64 {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from the controlled cgroupRoot
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// readCgroupMemoryEvents parses the key-value pairs in memory.events.
// Example file:
//
//	low 0
//	high 4
//	max 2
//	oom 1
//	oom_kill 1
//	oom_group_kill 0
func readCgroupMemoryEvents(path string) map[string]uint64 {
	out := make(map[string]uint64)
	f, err := os.Open(path) //nolint:gosec // path is constructed from the controlled cgroupRoot
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

// parseCgroupPod extracts a pod identifier from a cgroup path.
// Kubernetes uses paths like:
//
//	/sys/fs/cgroup/kubepods/burstable/pod<uid>/<container-id>
//
// Namespace resolution requires the Kubernetes API and is not done here;
// callers set Namespace="" and enrich later if needed.
func parseCgroupPod(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, p := range parts {
		if strings.HasPrefix(p, "pod") && len(p) > 3 {
			return p
		}
	}
	// Not a K8s-style path — use the last non-empty component.
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return filepath.Base(path)
}
