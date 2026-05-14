// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
)

// ─── syscallName ───────────────────────────────────────────────────────────

func TestSyscallName(t *testing.T) {
	tests := []struct {
		nr   uint32
		want string
	}{
		{0, "read"},
		{1, "write"},
		{2, "open"},
		{3, "close"},
		{59, "execve"},
		{257, "openat"},
		{99999, "syscall_99999"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := syscallName(tt.nr); got != tt.want {
				t.Errorf("syscallName(%d) = %q, want %q", tt.nr, got, tt.want)
			}
		})
	}
}

// ─── matchSyscallFilter ────────────────────────────────────────────────────

func TestMatchSyscallFilter(t *testing.T) {
	event := &bpf.SyscallEvent{SyscallNr: 0} // read

	tests := []struct {
		name   string
		filter string
		want   bool
	}{
		{"empty filter matches all", "", true},
		{"match by name", "read", true},
		{"match by name case insensitive", "READ", true},
		{"no match by name", "write", false},
		{"match by number", "0", true},
		{"no match by number", "1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSyscallFilter(event, tt.filter); got != tt.want {
				t.Errorf("matchSyscallFilter(nr=0, %q) = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}

// ─── matchDiskOp ───────────────────────────────────────────────────────────

func TestMatchDiskOp(t *testing.T) {
	tests := []struct {
		name   string
		op     byte
		filter string
		want   bool
	}{
		{"empty filter", 'R', "", true},
		{"read matches read", 'R', "read", true},
		{"read matches r", 'R', "r", true},
		{"write matches write", 'W', "write", true},
		{"sync matches sync", 'S', "sync", true},
		{"read does not match write", 'R', "write", false},
		{"unknown filter matches all", 'R', "foo", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &bpf.DiskEvent{Op: tt.op}
			if got := matchDiskOp(event, tt.filter); got != tt.want {
				t.Errorf("matchDiskOp(op=%c, %q) = %v, want %v", tt.op, tt.filter, got, tt.want)
			}
		})
	}
}

// ─── matchDiskProcess ──────────────────────────────────────────────────────

func TestMatchDiskProcess(t *testing.T) {
	event := &bpf.DiskEvent{}
	copy(event.Comm[:], "postgres")

	tests := []struct {
		name   string
		filter string
		want   bool
	}{
		{"empty filter", "", true},
		{"exact match", "postgres", true},
		{"case insensitive", "POSTGRES", true},
		{"no match", "mysql", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchDiskProcess(event, tt.filter); got != tt.want {
				t.Errorf("matchDiskProcess(%q) = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}

// ─── matchOOMThreshold ─────────────────────────────────────────────────────

func TestMatchOOMThreshold(t *testing.T) {
	tests := []struct {
		name      string
		score     int32
		threshold int64
		want      bool
	}{
		{"zero threshold matches all", 500, 0, true},
		{"score above threshold", 950, 500, true},
		{"score equals threshold", 500, 500, true},
		{"score below threshold", 100, 500, false},
		{"negative score", -17, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &bpf.OOMEvent{OOMScore: tt.score}
			if got := matchOOMThreshold(event, tt.threshold); got != tt.want {
				t.Errorf("matchOOMThreshold(score=%d, threshold=%d) = %v, want %v",
					tt.score, tt.threshold, got, tt.want)
			}
		})
	}
}

// ─── percentile ────────────────────────────────────────────────────────────

func TestPercentile(t *testing.T) {
	tests := []struct {
		name string
		data []time.Duration
		p    int
		want time.Duration
	}{
		{"empty", nil, 50, 0},
		{"single", []time.Duration{5 * time.Millisecond}, 50, 5 * time.Millisecond},
		{"p50 of 10 values", makeDurations(1, 10), 50, 6 * time.Millisecond},
		{"p99 of 100 values", makeDurations(1, 100), 99, 100 * time.Millisecond},
		{"p0 returns first", makeDurations(1, 10), 0, time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := percentile(tt.data, tt.p)
			if got != tt.want {
				t.Errorf("percentile(%d) = %v, want %v", tt.p, got, tt.want)
			}
		})
	}
}

// ─── formatLatency ─────────────────────────────────────────────────────────

func TestFormatLatency(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"nanoseconds", 500 * time.Nanosecond, "500ns"},
		{"microseconds", 1500 * time.Nanosecond, "1.5us"},
		{"milliseconds", 5 * time.Millisecond, "5.00ms"},
		{"seconds", 2 * time.Second, "2.00s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatLatency(tt.d); got != tt.want {
				t.Errorf("formatLatency(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

// ─── formatBytes ───────────────────────────────────────────────────────────

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		b    uint64
		want string
	}{
		{"bytes", 512, "512B"},
		{"kilobytes", 4096, "4.0KB"},
		{"megabytes", 1048576, "1.0MB"},
		{"gigabytes", 1073741824, "1.0GB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBytes(tt.b); got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.b, got, tt.want)
			}
		})
	}
}

// ─── formatDev ─────────────────────────────────────────────────────────────

func TestFormatDev(t *testing.T) {
	// Device 8:0 (sda) = major 8, minor 0
	// Encoding: (major << 20) | minor
	dev := uint32(8<<20 | 0)
	if got := formatDev(dev); got != "8:0" {
		t.Errorf("formatDev(%d) = %q, want %q", dev, got, "8:0")
	}
}

// ─── syscallEventJSON ──────────────────────────────────────────────────────

func TestSyscallEventJSON(t *testing.T) {
	event := &bpf.SyscallEvent{
		PID:       1234,
		TID:       1235,
		SyscallNr: 1,
		LatencyNs: 5_000_000,
		Ret:       0,
	}
	copy(event.Comm[:], "nginx")

	out := syscallEventJSON(event)

	if out.PID != 1234 {
		t.Errorf("PID = %d, want 1234", out.PID)
	}
	if out.Comm != "nginx" {
		t.Errorf("Comm = %q, want %q", out.Comm, "nginx")
	}
	if out.Syscall != "write" {
		t.Errorf("Syscall = %q, want %q", out.Syscall, "write")
	}
	if out.LatencyNs != 5_000_000 {
		t.Errorf("LatencyNs = %d, want 5000000", out.LatencyNs)
	}
}

// ─── diskEventJSON ─────────────────────────────────────────────────────────

func TestDiskEventJSON(t *testing.T) {
	event := &bpf.DiskEvent{
		LatencyNs: 250_000,
		PID:       4321,
		Op:        'W',
		NrBytes:   4096,
		Dev:       8 << 20,
		Sector:    1024,
	}
	copy(event.Comm[:], "postgres")

	out := diskEventJSON(event)

	if out.PID != 4321 {
		t.Errorf("PID = %d, want 4321", out.PID)
	}
	if out.Comm != "postgres" {
		t.Errorf("Comm = %q, want %q", out.Comm, "postgres")
	}
	if out.Op != "write" {
		t.Errorf("Op = %q, want %q", out.Op, "write")
	}
	if out.Bytes != 4096 {
		t.Errorf("Bytes = %d, want 4096", out.Bytes)
	}
}

// ─── schedEventJSON ────────────────────────────────────────────────────────

func TestSchedEventJSON(t *testing.T) {
	event := &bpf.SchedEvent{
		PID:         999,
		CPU:         3,
		RunqDelayNs: 15_000_000,
	}
	copy(event.Comm[:], "java")

	out := schedEventJSON(event)

	if out.PID != 999 {
		t.Errorf("PID = %d, want 999", out.PID)
	}
	if out.Comm != "java" {
		t.Errorf("Comm = %q, want %q", out.Comm, "java")
	}
	if out.CPU != 3 {
		t.Errorf("CPU = %d, want 3", out.CPU)
	}
	if out.RunqDelayNs != 15_000_000 {
		t.Errorf("RunqDelayNs = %d, want 15000000", out.RunqDelayNs)
	}
}

// ─── requireRoot ───────────────────────────────────────────────────────────

func TestRequireRoot(t *testing.T) {
	// Most test environments are non-root, so this should return an error.
	err := requireRoot()
	if err == nil {
		t.Skip("running as root, skipping non-root test")
	}
	if err.Error() != "this command requires root privileges (eBPF); re-run with sudo" {
		t.Errorf("unexpected error: %v", err)
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// makeDurations creates a slice of durations from start to end (inclusive) in milliseconds.
func makeDurations(startMs, endMs int) []time.Duration {
	d := make([]time.Duration, 0, endMs-startMs+1)
	for i := startMs; i <= endMs; i++ {
		d = append(d, time.Duration(i)*time.Millisecond)
	}
	return d
}
