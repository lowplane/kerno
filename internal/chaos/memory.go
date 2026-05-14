// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// MemoryScenario allocates memory progressively over its run window,
// touching every page so the kernel actually commits the pages. Pairs
// with the oom_imminent rule (predicts an OOM kill from growth rate).
type MemoryScenario struct{}

func init() { Register(MemoryScenario{}) }

// Name implements Scenario.
func (MemoryScenario) Name() string { return "memory" }

// Description implements Scenario.
func (MemoryScenario) Description() string {
	return "Grow resident memory steadily, touching every page"
}

// PairedRule implements Scenario.
func (MemoryScenario) PairedRule() string { return "oom_imminent" }

// Run implements Scenario.
func (s MemoryScenario) Run(ctx context.Context, opts Options) error {
	targetMB := memoryMBFromIntensity(opts.Intensity)
	fmt.Fprintf(opts.Out, "    allocating up to %d MB over %s\n", targetMB, opts.Duration)

	chunkBytes := 1 << 20 // 1 MB
	chunks := make([][]byte, 0, targetMB)

	growInterval := opts.Duration / time.Duration(targetMB)
	if growInterval <= 0 {
		growInterval = time.Millisecond
	}
	ticker := time.NewTicker(growInterval)
	defer ticker.Stop()

	for len(chunks) < targetMB {
		select {
		case <-ctx.Done():
			runtime.KeepAlive(chunks)
			return nil
		case <-ticker.C:
			buf := make([]byte, chunkBytes)
			// Touch every page (4K) so the kernel commits real RSS,
			// not just virtual address space.
			for i := 0; i < chunkBytes; i += 4096 {
				buf[i] = 0xff
			}
			chunks = append(chunks, buf)
		}
	}

	fmt.Fprintf(opts.Out, "    held %d MB resident; idling until duration expires\n", len(chunks))
	<-ctx.Done()
	runtime.KeepAlive(chunks)
	return nil
}

func memoryMBFromIntensity(intensity Intensity) int {
	switch intensity {
	case IntensityLow:
		return 64
	case IntensityHigh:
		return 512
	default:
		return 200
	}
}

// ─── CgroupMemoryScenario ────────────────────────────────────────────────────

// CgroupMemoryScenario creates a simulated cgroup v2 directory tree under
// /tmp with memory.max set to a finite limit and memory.current growing
// toward it. Pass KERNO_CGROUP_ROOT inline when invoking kerno doctor
// (e.g. KERNO_CGROUP_ROOT=<path> kerno doctor) so the env var is scoped
// to that process only and does not persist in the shell session.
//
// This pairs with the memory_limit_pressure rule.
type CgroupMemoryScenario struct{}

func init() { Register(CgroupMemoryScenario{}) }

func (CgroupMemoryScenario) Name() string { return "cgroup-memory" }
func (CgroupMemoryScenario) Description() string {
	return "Simulate a container approaching its cgroup memory.max limit"
}
func (CgroupMemoryScenario) PairedRule() string { return "memory_limit_pressure" }

// Run implements Scenario.
func (s CgroupMemoryScenario) Run(ctx context.Context, opts Options) error {
	limitMB := cgroupMemoryLimitMB(opts.Intensity)
	limitBytes := uint64(limitMB) << 20 //nolint:gosec // limitMB is a small controlled constant, no overflow risk

	cgroupDir := filepath.Join(os.TempDir(), "kerno-chaos-cgroup", "kubepods", "burstable", "pod-kerno-chaos", "container-0")
	if err := os.MkdirAll(cgroupDir, 0o750); err != nil { //nolint:gosec // temp dir for chaos simulation
		return fmt.Errorf("cgroup-memory: create dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(filepath.Join(os.TempDir(), "kerno-chaos-cgroup"))
	}()

	if err := os.WriteFile(filepath.Join(cgroupDir, "memory.max"), []byte(strconv.FormatUint(limitBytes, 10)+"\n"), 0o600); err != nil {
		return fmt.Errorf("cgroup-memory: write memory.max: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupDir, "memory.high"), []byte(strconv.FormatUint(limitBytes*9/10, 10)+"\n"), 0o600); err != nil {
		return fmt.Errorf("cgroup-memory: write memory.high: %w", err)
	}

	chaosRoot := filepath.Join(os.TempDir(), "kerno-chaos-cgroup")
	fmt.Fprintf(opts.Out, "    cgroup root: %s\n", chaosRoot)
	fmt.Fprintf(opts.Out, "    memory.max=%d MB, growing toward limit\n", limitMB)
	fmt.Fprintf(opts.Out, "    hint: KERNO_CGROUP_ROOT=%s kerno doctor\n", chaosRoot)

	// Grow current usage from 80 % to 97 % over the run duration.
	startBytes := limitBytes * 80 / 100
	endBytes := limitBytes * 97 / 100
	rangeBytes := endBytes - startBytes

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	start := time.Now()
	highEvents := uint64(0)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			elapsed := time.Since(start)
			frac := elapsed.Seconds() / opts.Duration.Seconds()
			if frac > 1.0 {
				frac = 1.0
			}
			current := startBytes + uint64(float64(rangeBytes)*frac)

			// Increment high events to simulate kernel reclaim pressure.
			if current >= limitBytes*85/100 {
				highEvents += 2
			}

			events := fmt.Sprintf("low 0\nhigh %d\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n", highEvents)
			if err := os.WriteFile(filepath.Join(cgroupDir, "memory.current"), []byte(strconv.FormatUint(current, 10)+"\n"), 0o600); err != nil {
				opts.Logger.Warn("cgroup-memory: failed to update memory.current", "error", err)
			}
			if err := os.WriteFile(filepath.Join(cgroupDir, "memory.events"), []byte(events), 0o600); err != nil {
				opts.Logger.Warn("cgroup-memory: failed to update memory.events", "error", err)
			}
		}
	}
}

func cgroupMemoryLimitMB(intensity Intensity) int {
	switch intensity {
	case IntensityLow:
		return 128
	case IntensityHigh:
		return 1024
	default:
		return 256
	}
}
