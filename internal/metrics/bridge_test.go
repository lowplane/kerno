// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/binary"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/optiqor/kerno/internal/bpf"
)

func TestRecordSyscall(t *testing.T) {
	tests := []struct {
		name       string
		syscallNr  uint32
		syscallStr string
		comm       string
	}{
		{
			name:       "write_syscall",
			syscallNr:  1,
			syscallStr: "write",
			comm:       "nginx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBridge(slog.Default())

			event := bpf.SyscallEvent{
				LatencyNs: 5_000_000,
				PID:       1234,
				SyscallNr: tt.syscallNr,
			}
			copy(event.Comm[:], tt.comm)
			data := encodeSyscallEvent(&event)

			before := testutil.ToFloat64(
				SyscallTotal.WithLabelValues(tt.syscallStr, tt.comm),
			)

			b.recordSyscall(bpf.RawEvent{Data: data})

			after := testutil.ToFloat64(
				SyscallTotal.WithLabelValues(tt.syscallStr, tt.comm),
			)

			if got := after - before; got != 1 {
				t.Errorf("SyscallTotal delta = %v, want 1", got)
			}
		})
	}
}

func TestRecordDiskIO(t *testing.T) {
	tests := []struct {
		name     string
		dev      uint32
		devLabel string
		op       byte
		opLabel  string
		bytes    uint32
	}{
		{
			name:     "disk_write",
			dev:      8 << 20,
			devLabel: "8:0",
			op:       'W',
			opLabel:  "write",
			bytes:    4096,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBridge(slog.Default())

			event := bpf.DiskEvent{
				LatencyNs: 250_000,
				Dev:       tt.dev,
				NrBytes:   tt.bytes,
				Op:        tt.op,
			}
			copy(event.Comm[:], "postgres")
			data := encodeDiskEvent(&event)

			before := testutil.ToFloat64(
				DiskIOBytesTotal.WithLabelValues(tt.devLabel, tt.opLabel),
			)

			b.recordDiskIO(bpf.RawEvent{Data: data})

			after := testutil.ToFloat64(
				DiskIOBytesTotal.WithLabelValues(tt.devLabel, tt.opLabel),
			)

			if got := after - before; got != float64(tt.bytes) {
				t.Errorf("DiskIOBytesTotal delta = %v, want %d", got, tt.bytes)
			}
		})
	}
}

func TestRecordOOM(t *testing.T) {
	tests := []struct {
		name string
		comm string
	}{
		{
			name: "oom_kill",
			comm: "oom-victim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBridge(slog.Default())

			event := bpf.OOMEvent{
				PID:      1234,
				OOMScore: 950,
			}
			copy(event.Comm[:], tt.comm)
			data := encodeOOMEvent(&event)

			before := testutil.ToFloat64(
				OOMKillsTotal.WithLabelValues(tt.comm),
			)

			b.recordOOM(bpf.RawEvent{Data: data})

			after := testutil.ToFloat64(
				OOMKillsTotal.WithLabelValues(tt.comm),
			)

			if got := after - before; got != 1 {
				t.Errorf("OOMKillsTotal delta = %v, want 1", got)
			}
		})
	}
}

func TestRecordFD(t *testing.T) {
	tests := []struct {
		name string
		op   bpf.FDOp
	}{
		{
			name: "fd_open",
			op:   bpf.FDOpOpen,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBridge(slog.Default())

			event := bpf.FDEvent{
				PID: 5678,
				FD:  42,
				Op:  tt.op,
			}
			copy(event.Comm[:], "leaky")
			data := encodeFDEvent(&event)

			before := testutil.ToFloat64(FDOpenTotal.WithLabelValues("leaky"))
			b.recordFD(bpf.RawEvent{Data: data})
			after := testutil.ToFloat64(FDOpenTotal.WithLabelValues("leaky"))

			if got := after - before; got != 1 {
				t.Errorf("FDOpenTotal delta = %v, want 1", got)
			}
		})
	}
}

func TestRecordSchedDelay(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "sched_delay_observe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBridge(slog.Default())

			event := bpf.SchedEvent{
				RunqDelayNs: 15_000_000,
				PID:         999,
				CPU:         3,
			}
			copy(event.Comm[:], "java")
			data := encodeSchedEvent(&event)

			b.recordSchedDelay(bpf.RawEvent{Data: data})
		})
	}
}

func TestCardinalityLimit(t *testing.T) {
	tests := []struct {
		name     string
		calls    int
		wantLast bool
	}{
		{
			name:     "at_limit",
			calls:    LabelCardinalityLimit,
			wantLast: true,
		},
		{
			name:     "one_past_limit",
			calls:    LabelCardinalityLimit + 1,
			wantLast: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBridge(slog.Default())

			var got bool
			for i := 0; i < tt.calls; i++ {
				got = b.cardinalityOK("test_metric")
			}

			if got != tt.wantLast {
				t.Fatalf("last cardinalityOK() = %v, want %v", got, tt.wantLast)
			}
		})
	}

	t.Run("different_metric_still_allowed", func(t *testing.T) {
		b := NewBridge(slog.Default())

		for i := 0; i < LabelCardinalityLimit+1; i++ {
			b.cardinalityOK("test_metric")
		}

		if !b.cardinalityOK("other_metric") {
			t.Error("expected cardinalityOK to return true for different metric")
		}
	})
}

func TestFormatDev(t *testing.T) {
	tests := []struct {
		name string
		dev  uint32
		want string
	}{
		{"8:0", 8<<20 | 0, "8:0"},
		{"8:1", 8<<20 | 1, "8:1"},
		{"259:0", 259<<20 | 0, "259:0"},
		{"259:1", 259<<20 | 1, "259:1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDev(tt.dev); got != tt.want {
				t.Errorf("formatDev(%d) = %q, want %q", tt.dev, got, tt.want)
			}
		})
	}
}

// syscallName resolution moved to bpf.SyscallName; the dedicated test
// lives in internal/bpf/decode_test.go.

// ─── Encoding helpers ─────────────────────────────────────────────────────
// These produce binary blobs matching the Go struct layout so
// bpf.Decode*Event can parse them.

func encodeSyscallEvent(e *bpf.SyscallEvent) []byte {
	buf := make([]byte, 64) // SyscallEvent is 56 bytes, pad for safety
	binary.LittleEndian.PutUint64(buf[0:], e.TimestampNs)
	binary.LittleEndian.PutUint64(buf[8:], e.LatencyNs)
	binary.LittleEndian.PutUint64(buf[16:], e.CgroupID)
	binary.LittleEndian.PutUint32(buf[24:], e.PID)
	binary.LittleEndian.PutUint32(buf[28:], e.TID)
	binary.LittleEndian.PutUint32(buf[32:], e.SyscallNr)
	binary.LittleEndian.PutUint32(buf[36:], e.Ret)
	copy(buf[40:56], e.Comm[:])
	return buf[:56]
}

func encodeDiskEvent(e *bpf.DiskEvent) []byte {
	buf := make([]byte, 64)
	binary.LittleEndian.PutUint64(buf[0:], e.TimestampNs)
	binary.LittleEndian.PutUint64(buf[8:], e.LatencyNs)
	binary.LittleEndian.PutUint64(buf[16:], e.Sector)
	binary.LittleEndian.PutUint32(buf[24:], e.Dev)
	binary.LittleEndian.PutUint32(buf[28:], e.NrBytes)
	binary.LittleEndian.PutUint32(buf[32:], e.PID)
	buf[36] = e.Op
	// pad [37:40]
	copy(buf[40:56], e.Comm[:])
	return buf[:56]
}

func encodeOOMEvent(e *bpf.OOMEvent) []byte {
	buf := make([]byte, 72)
	binary.LittleEndian.PutUint64(buf[0:], e.TimestampNs)
	binary.LittleEndian.PutUint64(buf[8:], e.CgroupID)
	binary.LittleEndian.PutUint64(buf[16:], e.TotalPages)
	binary.LittleEndian.PutUint64(buf[24:], e.RSSPages)
	binary.LittleEndian.PutUint32(buf[32:], e.PID)
	binary.LittleEndian.PutUint32(buf[36:], e.TriggeredPID)
	binary.LittleEndian.PutUint32(buf[40:], uint32(e.OOMScore))
	// pad [44:48]
	copy(buf[48:64], e.Comm[:])
	return buf[:64]
}

func encodeSchedEvent(e *bpf.SchedEvent) []byte {
	buf := make([]byte, 48)
	binary.LittleEndian.PutUint64(buf[0:], e.TimestampNs)
	binary.LittleEndian.PutUint64(buf[8:], e.RunqDelayNs)
	binary.LittleEndian.PutUint64(buf[16:], e.CgroupID)
	binary.LittleEndian.PutUint32(buf[24:], e.PID)
	binary.LittleEndian.PutUint32(buf[28:], e.CPU)
	copy(buf[32:48], e.Comm[:])
	return buf[:48]
}

func encodeFDEvent(e *bpf.FDEvent) []byte {
	buf := make([]byte, 48)
	binary.LittleEndian.PutUint64(buf[0:], e.TimestampNs)
	binary.LittleEndian.PutUint64(buf[8:], e.CgroupID)
	binary.LittleEndian.PutUint32(buf[16:], e.PID)
	binary.LittleEndian.PutUint32(buf[20:], uint32(e.FD))
	buf[24] = uint8(e.Op)
	// pad [25:32]
	copy(buf[32:48], e.Comm[:])
	return buf[:48]
}
