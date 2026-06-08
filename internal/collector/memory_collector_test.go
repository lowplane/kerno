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
		t.Run(c.in, func(t *testing.T) {
			k, v, ok := parseMeminfoLine(c.in)
			if ok != c.want {
				t.Errorf("parseMeminfoLine(%q) ok=%v, want %v", c.in, ok, c.want)
			}
			if ok && (k != c.key || v != c.val) {
				t.Errorf("parseMeminfoLine(%q) = (%q, %d), want (%q, %d)", c.in, k, v, c.key, c.val)
			}
		})
	}
}

func TestMemoryCollectorPoll(t *testing.T) {
	cases := []struct {
		name         string
		total        uint64
		available    uint64
		swapTotal    uint64
		swapFree     uint64
		wantTotal    uint64
		wantUsed     uint64
		wantAvail    uint64
		wantSwapUsed uint64
		wantPctLo    float64
		wantPctHi    float64
		wantErr      bool
	}{
		{
			name:         "half used with swap",
			total:        16 << 30,
			available:    8 << 30,
			swapTotal:    4 << 30,
			swapFree:     2 << 30,
			wantTotal:    16 << 30,
			wantUsed:     8 << 30,
			wantAvail:    8 << 30,
			wantSwapUsed: 2 << 30,
			wantPctLo:    49.9,
			wantPctHi:    50.1,
		},
		{
			name:      "no swap configured",
			total:     8 << 30,
			available: 4 << 30,
			wantTotal: 8 << 30,
			wantUsed:  4 << 30,
			wantAvail: 4 << 30,
			wantPctLo: 49.9,
			wantPctHi: 50.1,
		},
		{
			name:      "swapfree exceeds swaptotal, guard clamps to zero",
			total:     4 << 30,
			available: 2 << 30,
			swapTotal: 1 << 30,
			swapFree:  2 << 30,
			wantTotal: 4 << 30,
			wantUsed:  2 << 30,
			wantAvail: 2 << 30,
			wantPctLo: 49.9,
			wantPctHi: 50.1,
		},
		{
			name:      "fully used memory",
			total:     4 << 30,
			available: 0,
			wantTotal: 4 << 30,
			wantUsed:  4 << 30,
			wantPctLo: 99.9,
			wantPctHi: 100.1,
		},
		{
			name:      "exactly at 75 percent used",
			total:     4 << 30,
			available: 1 << 30,
			wantTotal: 4 << 30,
			wantUsed:  3 << 30,
			wantAvail: 1 << 30,
			wantPctLo: 74.9,
			wantPctHi: 75.1,
		},
		{
			name:    "zero total returns error",
			total:   0,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeMeminfo(t, c.total, c.available, c.swapTotal, c.swapFree)
			col := NewMemoryCollector(newSilentLogger(), 50*time.Millisecond)
			col.procPath = path

			err := col.poll()
			if c.wantErr {
				if err == nil {
					t.Fatal("expected poll error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("poll: %v", err)
			}

			snap, ok := col.Snapshot().(*MemorySnapshot)
			if !ok || snap == nil {
				t.Fatal("expected non-nil snapshot")
			}
			if snap.TotalBytes != c.wantTotal {
				t.Errorf("TotalBytes = %d, want %d", snap.TotalBytes, c.wantTotal)
			}
			if snap.UsedBytes != c.wantUsed {
				t.Errorf("UsedBytes = %d, want %d", snap.UsedBytes, c.wantUsed)
			}
			if snap.AvailableBytes != c.wantAvail {
				t.Errorf("AvailableBytes = %d, want %d", snap.AvailableBytes, c.wantAvail)
			}
			if snap.SwapUsedBytes != c.wantSwapUsed {
				t.Errorf("SwapUsedBytes = %d, want %d", snap.SwapUsedBytes, c.wantSwapUsed)
			}
			if snap.UsedPct < c.wantPctLo || snap.UsedPct > c.wantPctHi {
				t.Errorf("UsedPct = %v, want [%v, %v]", snap.UsedPct, c.wantPctLo, c.wantPctHi)
			}
		})
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
