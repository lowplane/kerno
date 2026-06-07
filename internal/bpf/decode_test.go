// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// encode marshals a fixed-size struct to bytes using little-endian
func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeSyscallEvent(t *testing.T) {
	validEvent := SyscallEvent{
		TimestampNs: 12345,
		LatencyNs:   1_500_000,
		CgroupID:    99,
		PID:         100,
		TID:         101,
		SyscallNr:   257,
		Ret:         0,
	}
	copy(validEvent.Comm[:], "myproc")
	validData := encode(t, &validEvent)
	oversizedData := append([]byte(nil), validData...)
	oversizedData = append(oversizedData, []byte{0xFF, 0xFE, 0xFD}...)

	tests := []struct {
		name    string
		raw     []byte
		want    *SyscallEvent
		wantErr bool
	}{
		{"exact size", validData, &validEvent, false},
		{"short buffer", []byte{1, 2, 3}, nil, true},
		{"oversized buffer", oversizedData, &validEvent, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeSyscallEvent(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.PID != tt.want.PID {
				t.Errorf("PID = %d, want %d", got.PID, tt.want.PID)
			}
			if got.SyscallNr != tt.want.SyscallNr {
				t.Errorf("SyscallNr = %d, want %d", got.SyscallNr, tt.want.SyscallNr)
			}
			if got.CommString() != tt.want.CommString() {
				t.Errorf("CommString = %q, want %q", got.CommString(), tt.want.CommString())
			}
			if got.Latency() != tt.want.Latency() {
				t.Errorf("Latency = %v, want %v", got.Latency(), tt.want.Latency())
			}
			if got.TimestampNs != tt.want.TimestampNs {
				t.Errorf("TimestampNs = %d, want %d", got.TimestampNs, tt.want.TimestampNs)
			}
			if got.CgroupID != tt.want.CgroupID {
				t.Errorf("CgroupID = %d, want %d", got.CgroupID, tt.want.CgroupID)
			}
			if got.TID != tt.want.TID {
				t.Errorf("TID = %d, want %d", got.TID, tt.want.TID)
			}
			if got.Ret != tt.want.Ret {
				t.Errorf("Ret = %d, want %d", got.Ret, tt.want.Ret)
			}
		})
	}
}

func TestDecodeTCPEvent(t *testing.T) {
	validEvent := TCPEvent{
		TimestampNs: 9999,
		PID:         42,
		SAddr:       binary.BigEndian.Uint32([]byte{10, 0, 0, 1}),
		DAddr:       binary.BigEndian.Uint32([]byte{8, 8, 8, 8}),
		SPort:       54321,
		DPort:       443,
		EventType:   TCPEventRTT,
		RTTUs:       250,
	}
	copy(validEvent.Comm[:], "curl")
	validData := encode(t, &validEvent)
	oversizedData := append([]byte(nil), validData...)
	oversizedData = append(oversizedData, []byte{0xAA, 0xBB}...)

	tests := []struct {
		name    string
		raw     []byte
		want    *TCPEvent
		wantErr bool
	}{
		{"exact size", validData, &validEvent, false},
		{"short buffer", []byte{1, 2, 3, 4}, nil, true},
		{"oversized buffer", oversizedData, &validEvent, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeTCPEvent(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.SrcAddr().String() != tt.want.SrcAddr().String() {
				t.Errorf("SrcAddr = %s, want %s", got.SrcAddr(), tt.want.SrcAddr())
			}
			if got.DstAddr().String() != tt.want.DstAddr().String() {
				t.Errorf("DstAddr = %s, want %s", got.DstAddr(), tt.want.DstAddr())
			}
			if got.RTT().Microseconds() != tt.want.RTT().Microseconds() {
				t.Errorf("RTT = %v, want %v", got.RTT(), tt.want.RTT())
			}
			if got.PID != tt.want.PID {
				t.Errorf("PID = %d, want %d", got.PID, tt.want.PID)
			}
			if got.SPort != tt.want.SPort {
				t.Errorf("SPort = %d, want %d", got.SPort, tt.want.SPort)
			}
			if got.DPort != tt.want.DPort {
				t.Errorf("DPort = %d, want %d", got.DPort, tt.want.DPort)
			}
			if got.EventType != tt.want.EventType {
				t.Errorf("EventType = %v, want %v", got.EventType, tt.want.EventType)
			}
			if got.CommString() != tt.want.CommString() {
				t.Errorf("CommString = %q, want %q", got.CommString(), tt.want.CommString())
			}
		})
	}
}

func TestDecodeOOMEvent(t *testing.T) {
	validEvent := OOMEvent{
		TimestampNs:  555,
		CgroupID:     1,
		TotalPages:   1_000_000,
		RSSPages:     800_000,
		PID:          7,
		TriggeredPID: 8,
		OOMScore:     900,
	}
	copy(validEvent.Comm[:], "victim")
	validData := encode(t, &validEvent)
	oversizedData := append([]byte(nil), validData...)
	oversizedData = append(oversizedData, []byte{0xCC, 0xDD}...)

	tests := []struct {
		name    string
		raw     []byte
		want    *OOMEvent
		wantErr bool
	}{
		{"exact size", validData, &validEvent, false},
		{"short buffer", []byte{0x01}, nil, true},
		{"oversized buffer", oversizedData, &validEvent, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeOOMEvent(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.RSSPages != tt.want.RSSPages {
				t.Errorf("RSSPages = %d, want %d", got.RSSPages, tt.want.RSSPages)
			}
			if got.CommString() != tt.want.CommString() {
				t.Errorf("CommString = %q, want %q", got.CommString(), tt.want.CommString())
			}
			if got.TotalPages != tt.want.TotalPages {
				t.Errorf("TotalPages = %d, want %d", got.TotalPages, tt.want.TotalPages)
			}
			if got.PID != tt.want.PID {
				t.Errorf("PID = %d, want %d", got.PID, tt.want.PID)
			}
			if got.TriggeredPID != tt.want.TriggeredPID {
				t.Errorf("TriggeredPID = %d, want %d", got.TriggeredPID, tt.want.TriggeredPID)
			}
			if got.OOMScore != tt.want.OOMScore {
				t.Errorf("OOMScore = %d, want %d", got.OOMScore, tt.want.OOMScore)
			}
		})
	}
}

func TestDecodeDiskEvent(t *testing.T) {
	validEvent := DiskEvent{
		TimestampNs: 1,
		LatencyNs:   500_000,
		Sector:      4096,
		Dev:         8,
		NrBytes:     4096,
		PID:         123,
		Op:          'R',
	}
	copy(validEvent.Comm[:], "fio")
	validData := encode(t, &validEvent)
	oversizedData := append([]byte(nil), validData...)
	oversizedData = append(oversizedData, []byte{0xEE, 0xFF}...)

	tests := []struct {
		name    string
		raw     []byte
		want    *DiskEvent
		wantErr bool
	}{
		{"exact size", validData, &validEvent, false},
		{"short buffer", []byte{0x00}, nil, true},
		{"oversized buffer", oversizedData, &validEvent, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeDiskEvent(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.OpString() != tt.want.OpString() {
				t.Errorf("OpString = %q, want %q", got.OpString(), tt.want.OpString())
			}
			if got.CommString() != tt.want.CommString() {
				t.Errorf("CommString = %q, want %q", got.CommString(), tt.want.CommString())
			}
			if got.NrBytes != tt.want.NrBytes {
				t.Errorf("NrBytes = %d, want %d", got.NrBytes, tt.want.NrBytes)
			}
			if got.Latency() != tt.want.Latency() {
				t.Errorf("Latency = %v, want %v", got.Latency(), tt.want.Latency())
			}
		})
	}
}

func TestDecodeSchedEvent(t *testing.T) {
	validEvent := SchedEvent{
		TimestampNs: 1,
		RunqDelayNs: 2_000_000,
		PID:         1,
		CPU:         0,
	}
	copy(validEvent.Comm[:], "kworker")
	validData := encode(t, &validEvent)
	oversizedData := append([]byte(nil), validData...)
	oversizedData = append(oversizedData, []byte{0x11, 0x22}...)

	tests := []struct {
		name    string
		raw     []byte
		want    *SchedEvent
		wantErr bool
	}{
		{"exact size", validData, &validEvent, false},
		{"short buffer", []byte{0x00}, nil, true},
		{"oversized buffer", oversizedData, &validEvent, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeSchedEvent(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.RunqDelay().Microseconds() != tt.want.RunqDelay().Microseconds() {
				t.Errorf("RunqDelay = %v, want %v", got.RunqDelay(), tt.want.RunqDelay())
			}
			if got.PID != tt.want.PID {
				t.Errorf("PID = %d, want %d", got.PID, tt.want.PID)
			}
			if got.CPU != tt.want.CPU {
				t.Errorf("CPU = %d, want %d", got.CPU, tt.want.CPU)
			}
			if got.CommString() != tt.want.CommString() {
				t.Errorf("CommString = %q, want %q", got.CommString(), tt.want.CommString())
			}
		})
	}
}

func TestDecodeFDEvent(t *testing.T) {
	validEvent := FDEvent{
		TimestampNs: 1,
		PID:         42,
		FD:          7,
		Op:          FDOpOpen,
	}
	copy(validEvent.Comm[:], "leakr")
	validData := encode(t, &validEvent)
	oversizedData := append([]byte(nil), validData...)
	oversizedData = append(oversizedData, []byte{0x77, 0x88}...)

	tests := []struct {
		name    string
		raw     []byte
		want    *FDEvent
		wantErr bool
	}{
		{"exact size", validData, &validEvent, false},
		{"short buffer", []byte{0x00}, nil, true},
		{"oversized buffer", oversizedData, &validEvent, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeFDEvent(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Op != tt.want.Op {
				t.Errorf("Op = %v, want %v", got.Op, tt.want.Op)
			}
			if got.Op.String() != tt.want.Op.String() {
				t.Errorf("Op.String() = %q, want %q", got.Op.String(), tt.want.Op.String())
			}
			if got.PID != tt.want.PID {
				t.Errorf("PID = %d, want %d", got.PID, tt.want.PID)
			}
			if got.FD != tt.want.FD {
				t.Errorf("FD = %d, want %d", got.FD, tt.want.FD)
			}
			if got.CommString() != tt.want.CommString() {
				t.Errorf("CommString = %q, want %q", got.CommString(), tt.want.CommString())
			}
		})
	}
}

func TestTCPEventTypeStringRoundTrip(t *testing.T) {
	cases := map[TCPEventType]string{
		TCPEventConnect:    "connect",
		TCPEventClose:      "close",
		TCPEventRetransmit: "retransmit",
		TCPEventRTT:        "rtt",
		TCPEventType(99):   "unknown(99)",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", k, got, want)
		}
	}
}

func TestDiskEventOpStrings(t *testing.T) {
	cases := []struct {
		op   byte
		want string
	}{
		{'R', "read"},
		{'W', "write"},
		{'S', "sync"},
		{'X', "unknown(X)"},
	}
	for _, c := range cases {
		e := DiskEvent{Op: c.op}
		if got := e.OpString(); got != c.want {
			t.Errorf("OpString(%c) = %q, want %q", c.op, got, c.want)
		}
	}
}

func TestFDOpStringRoundTrip(t *testing.T) {
	cases := map[FDOp]string{
		FDOpOpen:  "open",
		FDOpClose: "close",
		FDOp(99):  "unknown(99)",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q", k, got)
		}
	}
}

func TestEventTypeString(t *testing.T) {
	cases := map[EventType]string{
		EventSyscallLatency: "syscall_latency",
		EventTCPMonitor:     "tcp_monitor",
		EventOOMKill:        "oom_kill",
		EventDiskIO:         "disk_io",
		EventSchedDelay:     "sched_delay",
		EventFDTrack:        "fd_track",
		EventFileAudit:      "file_audit",
		EventType(99):       "unknown(99)",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q", k, got)
		}
	}
}

func TestNullTermStringTable(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{'a', 'b', 'c', 0, 'x', 'y'}, "abc"},
		{[]byte{0, 'a', 'b'}, ""},
		{[]byte("noterminator"), "noterminator"},
		{[]byte{}, ""},
	}
	for _, c := range cases {
		if got := nullTermString(c.in); got != c.want {
			t.Errorf("nullTermString(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSyscallNameKnown(t *testing.T) {
	cases := map[uint32]string{
		0:   "read",
		1:   "write",
		74:  "fsync",
		257: "openat",
		999: "syscall_999",
	}
	for nr, want := range cases {
		if got := SyscallName(nr); got != want {
			t.Errorf("SyscallName(%d) = %q, want %q", nr, got, want)
		}
	}
}

func TestIsSyscallError(t *testing.T) {
	if IsSyscallError(0) {
		t.Error("0 should not be an error")
	}
	if IsSyscallError(100) {
		t.Error("100 should not be an error")
	}
	if !IsSyscallError(0xFFFFFFF5) {
		t.Error("-EAGAIN (0xFFFFFFF5) should be an error")
	}
	if !IsSyscallError(0xFFFFFFFF) {
		t.Error("-EPERM should be an error")
	}
}

var _ = net.IPv4(0, 0, 0, 0)
