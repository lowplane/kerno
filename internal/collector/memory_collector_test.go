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

func writeMeminfo(t *testing.T, total, available, swapTotal, swapFree uint64) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "meminfo")
	content := ""
	content += "MemTotal:       " + uintK(total) + " kB\n"
	content += "MemAvailable:   " + uintK(available) + " kB\n"
	content += "SwapTotal:      " + uintK(swapTotal) + " kB\n"
	content += "SwapFree:       " + uintK(swapFree) + " kB\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func uintK(b uint64) string {
	// Convert bytes to "kB" string for /proc/meminfo emulation.
	return formatUintBase10(b / 1024)
}

func formatUintBase10(v uint64) string {
	if v == 0 {
		return "0"
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte('0' + v%10)}, out...)
		v /= 10
	}
	return string(out)
}

func TestParseMeminfoLine(t *testing.T) {
	cases := []struct {
		in   string
		key  string
		val  uint64
		want bool
	}{
		{"MemTotal:       16284980 kB", "MemTotal", 16284980, true},
		{"MemAvailable:   12345 kB", "MemAvailable", 12345, true},
		{"Hugepagesize:   2048 kB", "Hugepagesize", 2048, true},
		{"VmallocTotal:   34359738367 kB", "VmallocTotal", 34359738367, true},
		{"NoColonHere", "", 0, false},
		{"BadValue:       not_a_number kB", "", 0, false},
	}
	for _, c := range cases {
		k, v, ok := parseMeminfoLine(c.in)
		if ok != c.want {
			t.Errorf("parseMeminfoLine(%q) ok=%v, want %v", c.in, ok, c.want)
		}
		if ok && (k != c.key || v != c.val) {
			t.Errorf("parseMeminfoLine(%q) = (%q, %d), want (%q, %d)", c.in, k, v, c.key, c.val)
		}
	}
}

func TestMemoryCollectorPoll(t *testing.T) {
	path := writeMeminfo(t, 16<<30, 8<<30, 4<<30, 2<<30) // 16GB total, 8GB avail

	c := NewMemoryCollector(newSilentLogger(), 50*time.Millisecond)
	c.procPath = path

	if err := c.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}

	snap, ok := c.Snapshot().(*MemorySnapshot)
	if !ok || snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.TotalBytes != 16<<30 {
		t.Errorf("TotalBytes = %d, want %d", snap.TotalBytes, uint64(16<<30))
	}
	if snap.UsedBytes != 8<<30 {
		t.Errorf("UsedBytes = %d, want %d", snap.UsedBytes, uint64(8<<30))
	}
	if snap.AvailableBytes != 8<<30 {
		t.Errorf("AvailableBytes = %d, want %d", snap.AvailableBytes, uint64(8<<30))
	}
	if snap.SwapUsedBytes != 2<<30 {
		t.Errorf("SwapUsedBytes = %d, want %d", snap.SwapUsedBytes, uint64(2<<30))
	}
	// Used pct should be ~50%.
	if snap.UsedPct < 49.0 || snap.UsedPct > 51.0 {
		t.Errorf("UsedPct = %v, want ~50", snap.UsedPct)
	}
}

func TestMemoryCollectorGrowthRate(t *testing.T) {
	path := writeMeminfo(t, 16<<30, 8<<30, 0, 0)

	c := NewMemoryCollector(newSilentLogger(), 10*time.Millisecond)
	c.procPath = path

	if err := c.poll(); err != nil {
		t.Fatal(err)
	}

	// Wait, then write a new meminfo with less available memory (i.e.,
	// memory grew) and poll again.
	time.Sleep(50 * time.Millisecond)
	avail := uint64(7) << 30 // dropped 1 GiB available
	content := "MemTotal:       " + uintK(16<<30) + " kB\n"
	content += "MemAvailable:   " + uintK(avail) + " kB\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.poll(); err != nil {
		t.Fatal(err)
	}
	snap := c.Snapshot().(*MemorySnapshot)
	if snap.GrowthRateBytesPerSec <= 0 {
		t.Errorf("growth rate = %v, want > 0 (memory increased)", snap.GrowthRateBytesPerSec)
	}
}

func TestMemoryCollectorStartStop(t *testing.T) {
	path := writeMeminfo(t, 4<<30, 2<<30, 0, 0)

	c := NewMemoryCollector(newSilentLogger(), 25*time.Millisecond)
	c.procPath = path

	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Let a few polls happen.
	time.Sleep(120 * time.Millisecond)

	cancel()
	c.Stop()

	if c.Snapshot() == nil {
		t.Error("expected non-nil snapshot after Start+polls")
	}
}

func TestMemoryCollectorEmptySnapshotBeforeStart(t *testing.T) {
	c := NewMemoryCollector(newSilentLogger(), time.Second)
	if c.Snapshot() != nil {
		t.Error("snapshot should be nil before any successful poll")
	}
}
