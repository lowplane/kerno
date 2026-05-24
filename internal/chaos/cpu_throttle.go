// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// CPUThrottleScenario creates cgroup CPU throttling in-process by spawning
// goroutines that spin hard while the Go runtime's GOMAXPROCS is reduced to
// a tiny value, simulating a container that hits its CFS quota. The
// ThrottledCgroupRoot env var is set so the collector reads a synthetic
// cpu.stat fixture written to /tmp, making the rule fire without requiring
// real cgroup writes (which need root/CAP_SYS_ADMIN).
//
// In CI and on developer laptops the scenario works entirely in-process:
// no external commands, no /sys writes, no root required.
package chaos

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// CPUThrottleScenario simulates cgroup CPU throttling by:
//  1. Writing a synthetic cpu.stat fixture under /tmp with a high throttle pct.
//  2. Setting KERNO_CGROUP_ROOT to point the collector at that fixture.
//  3. Spinning goroutines so real CPU usage climbs (making the scenario
//     realistic even on bare metal where no real CFS quota exists).
type CPUThrottleScenario struct{}

func init() { Register(CPUThrottleScenario{}) }

// Name implements Scenario.
func (CPUThrottleScenario) Name() string { return "cpu-throttle" }

// Description implements Scenario.
func (CPUThrottleScenario) Description() string {
	return "Simulate cgroup CFS CPU throttling (synthetic cpu.stat fixture + spin workers)"
}

// PairedRule implements Scenario.
func (CPUThrottleScenario) PairedRule() string { return "cpu_throttled" }

// Run implements Scenario.
func (s CPUThrottleScenario) Run(ctx context.Context, opts Options) error {
	// ── 1. Write synthetic cpu.stat fixture ────────────────────────────────
	fixtureDir := filepath.Join(os.TempDir(), "kerno-chaos-cpu-throttle")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		return fmt.Errorf("cpu-throttle: create fixture dir: %w", err)
	}
	defer os.RemoveAll(fixtureDir)

	// Write initial cpu.stat with throttle_pct well above the 25% threshold.
	// The collector computes delta so we write large absolute values; the
	// first poll will see them as the delta (prev == 0).
	throttleLevel := throttleLevelFromIntensity(opts.Intensity)
	if err := writeCPUStat(fixtureDir, throttleLevel); err != nil {
		return fmt.Errorf("cpu-throttle: write cpu.stat: %w", err)
	}

	// Point the cgroup_throttle collector at our fixture directory.
	prevRoot := os.Getenv("KERNO_CGROUP_ROOT")
	os.Setenv("KERNO_CGROUP_ROOT", fixtureDir) //nolint:errcheck
	defer func() {
		if prevRoot == "" {
			os.Unsetenv("KERNO_CGROUP_ROOT") //nolint:errcheck
		} else {
			os.Setenv("KERNO_CGROUP_ROOT", prevRoot) //nolint:errcheck
		}
	}()

	// ── 2. Spin CPU workers so the scenario has real CPU impact ────────────
	workers := workersFromIntensity(opts.Intensity, runtime.NumCPU())
	fmt.Fprintf(opts.Out, "  spawning %d CPU spin workers, throttle_pct=%.0f%%\n",
		workers, throttleLevel.pct)

	var sink atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed)) //nolint:gosec
			for ctx.Err() == nil {
				var local float64
				for k := 0; k < 50_000 && ctx.Err() == nil; k++ {
					local += math.Sqrt(r.Float64())
				}
				sink.Add(uint64(local))
			}
		}(int64(i))
	}

	// ── 3. Refresh the synthetic cpu.stat every 5s so deltas stay high ─────
	refreshTicker := time.NewTicker(5 * time.Second)
	defer refreshTicker.Stop()
	var counter uint64 = 0
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-refreshTicker.C:
			counter++
			tl := throttleLevel
			tl.nrPeriods += counter * 100
			tl.nrThrottled += counter * uint64(float64(100)*tl.pct/100)
			tl.throttledUs += counter * 250_000
			if err := writeCPUStat(fixtureDir, tl); err != nil {
				opts.Logger.Debug("cpu-throttle: refresh cpu.stat failed", "error", err)
			}
		}
	}

	wg.Wait()
	_ = sink.Load()
	return nil
}

type throttleSpec struct {
	nrPeriods   uint64
	nrThrottled uint64
	throttledUs uint64
	pct         float64
}

func throttleLevelFromIntensity(intensity Intensity) throttleSpec {
	switch intensity {
	case IntensityLow:
		return throttleSpec{nrPeriods: 100, nrThrottled: 30, throttledUs: 150_000, pct: 30}
	case IntensityHigh:
		return throttleSpec{nrPeriods: 100, nrThrottled: 80, throttledUs: 640_000, pct: 80}
	default:
		return throttleSpec{nrPeriods: 100, nrThrottled: 50, throttledUs: 400_000, pct: 50}
	}
}

func writeCPUStat(dir string, ts throttleSpec) error {
	usageUs := ts.nrPeriods * 5_000 // synthetic
	content := fmt.Sprintf(
		"usage_usec %d\nnr_periods %d\nnr_throttled %d\nthrottled_usec %d\n",
		usageUs, ts.nrPeriods, ts.nrThrottled, ts.throttledUs,
	)
	return os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(content), 0o644) //nolint:gosec
}
