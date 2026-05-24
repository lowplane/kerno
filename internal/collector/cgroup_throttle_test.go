// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0
package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFakeCPUStat writes a cpu.stat file in the given directory.
func writeFakeCPUStat(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(content), 0o644); err != nil {
		t.Fatalf("writeFakeCPUStat: %v", err)
	}
}

// TestCgroupThrottleCollector_NoThrottle verifies that a cgroup with zero
// throttled periods emits no entries (bare-metal invariant).
func TestCgroupThrottleCollector_NoThrottle(t *testing.T) {
	dir := t.TempDir()
	writeFakeCPUStat(t, dir, "usage_usec 100\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n")

	t.Setenv("KERNO_CGROUP_ROOT", dir)

	logger := testLogger(t)
	c := NewCgroupThrottleCollector(logger, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-ctx.Done()
	c.Stop()

	snap := c.Snapshot()
	if snap != nil {
		t.Errorf("expected nil snapshot for zero throttle, got %v", snap)
	}
}

// TestCgroupThrottleCollector_Throttled verifies that a cgroup with
// nr_throttled > 25% of nr_periods produces a non-nil snapshot.
func TestCgroupThrottleCollector_Throttled(t *testing.T) {
	dir := t.TempDir()
	// nr_throttled=50 / nr_periods=100 = 50% throttle
	writeFakeCPUStat(t, dir, "usage_usec 500000\nnr_periods 100\nnr_throttled 50\nthrottled_usec 400000\n")

	t.Setenv("KERNO_CGROUP_ROOT", dir)

	logger := testLogger(t)
	c := NewCgroupThrottleCollector(logger, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-ctx.Done()
	c.Stop()

	snap := c.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot for throttled cgroup")
	}
	throttle := snap.(*CPUThrottleSnapshot)
	if len(throttle.Containers) == 0 {
		t.Fatal("expected at least one container entry")
	}
	entry := throttle.Containers[0]
	if entry.NrPeriods == 0 {
		t.Error("NrPeriods should not be zero")
	}
}

// TestReadCPUStat verifies the parser handles standard cpu.stat output.
func TestReadCPUStat(t *testing.T) {
	dir := t.TempDir()
	writeFakeCPUStat(t, dir, "usage_usec 12345678\nnr_periods 100\nnr_throttled 47\nthrottled_usec 320000\n")

	result := readCPUStat(filepath.Join(dir, "cpu.stat"))

	assertEq(t, "nr_periods", result["nr_periods"], uint64(100))
	assertEq(t, "nr_throttled", result["nr_throttled"], uint64(47))
	assertEq(t, "throttled_usec", result["throttled_usec"], uint64(320000))
}

// TestThrottlePct checks boundary conditions for throttle percentage math.
func TestThrottlePct(t *testing.T) {
	tests := []struct {
		nrThrottled uint64
		nrPeriods   uint64
		want        float64
	}{
		{0, 0, 0},
		{0, 100, 0},
		{50, 100, 50.0},
		{100, 100, 100.0},
		{47, 100, 47.0},
	}
	for _, tc := range tests {
		got := throttlePct(tc.nrThrottled, tc.nrPeriods)
		if got != tc.want {
			t.Errorf("throttlePct(%d,%d)=%.1f want %.1f", tc.nrThrottled, tc.nrPeriods, got, tc.want)
		}
	}
}

// TestDiffUint64 verifies counter-reset protection.
func TestDiffUint64(t *testing.T) {
	if d := diffUint64(100, 60); d != 40 {
		t.Errorf("expected 40, got %d", d)
	}
	// Counter reset: current < prev.
	if d := diffUint64(10, 100); d != 10 {
		t.Errorf("expected 10 on reset, got %d", d)
	}
}

func assertEq(t *testing.T, name string, got, want uint64) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %d, want %d", name, got, want)
	}
}
