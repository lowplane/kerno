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
// (matches eBPF C ring buffer layout on amd64/arm64).
func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeSyscallEventRoundTrip(t *testing.T) {
	want := SyscallEvent{
		TimestampNs: 12345,
		LatencyNs:   1_500_000,
		CgroupID:    99,
		PID:         100,
		TID:         101,
		SyscallNr:   257, // openat
		Ret:         0,
	}
	copy(want.Comm[:], "myproc")

	data := encode(t, &want)
	got, err := DecodeSyscallEvent(data)
	if err != nil {
		t.Fatalf("DecodeSyscallEvent error: %v", err)
	}
	if got.PID != want.PID || got.SyscallNr != want.SyscallNr {
		t.Errorf("got = %+v, want = %+v", got, want)
	}
	if got.CommString() != "myproc" {
		t.Errorf("CommString = %q, want myproc", got.CommString())
	}
	if got.Latency() != want.Latency() {
		t.Errorf("Latency() = %v, want %v", got.Latency(), want.Latency())
	}
}

func TestDecodeSyscallEventTooShort(t *testing.T) {
	if _, err := DecodeSyscallEvent([]byte{1, 2, 3}); err == nil {
		t.Error("expected error on undersized buffer")
	}
}

func TestDecodeTCPEventRoundTrip(t *testing.T) {
	want := TCPEvent{
		TimestampNs: 9999,
		PID:         42,
		SAddr:       binary.BigEndian.Uint32([]byte{10, 0, 0, 1}),
		DAddr:       binary.BigEndian.Uint32([]byte{8, 8, 8, 8}),
		SPort:       54321,
		DPort:       443,
		EventType:   TCPEventRTT,
		RTTUs:       250,
	}
	copy(want.Comm[:], "curl")

	data := encode(t, &want)
	got, err := DecodeTCPEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcAddr().String() != "10.0.0.1" {
		t.Errorf("SrcAddr = %s, want 10.0.0.1", got.SrcAddr())
	}
	if got.DstAddr().String() != "8.8.8.8" {
		t.Errorf("DstAddr = %s, want 8.8.8.8", got.DstAddr())
	}
	if got.RTT().Microseconds() != 250 {
		t.Errorf("RTT = %v, want 250µs", got.RTT())
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

func TestDecodeOOMEventRoundTrip(t *testing.T) {
	want := OOMEvent{
		TimestampNs:  555,
		CgroupID:     1,
		TotalPages:   1_000_000,
		RSSPages:     800_000,
		PID:          7,
		TriggeredPID: 8,
		OOMScore:     900,
	}
	copy(want.Comm[:], "victim")

	data := encode(t, &want)
	got, err := DecodeOOMEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.RSSPages != want.RSSPages {
		t.Errorf("RSSPages = %d, want %d", got.RSSPages, want.RSSPages)
	}
	if got.CommString() != "victim" {
		t.Errorf("CommString = %q", got.CommString())
	}
}

func TestDecodeDiskEventRoundTrip(t *testing.T) {
	want := DiskEvent{
		TimestampNs: 1,
		LatencyNs:   500_000,
		Sector:      4096,
		Dev:         8,
		NrBytes:     4096,
		PID:         123,
		Op:          'R',
	}
	copy(want.Comm[:], "fio")

	data := encode(t, &want)
	got, err := DecodeDiskEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.OpString() != "read" {
		t.Errorf("OpString = %q, want read", got.OpString())
	}
	if got.CommString() != "fio" {
		t.Errorf("CommString = %q", got.CommString())
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

func TestDecodeSchedEventRoundTrip(t *testing.T) {
	want := SchedEvent{
		TimestampNs: 1,
		RunqDelayNs: 2_000_000,
		PID:         1,
		CPU:         0,
	}
	copy(want.Comm[:], "kworker")

	data := encode(t, &want)
	got, err := DecodeSchedEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.RunqDelay().Microseconds() != 2000 {
		t.Errorf("RunqDelay = %v, want 2ms", got.RunqDelay())
	}
}

func TestDecodeFDEventRoundTrip(t *testing.T) {
	want := FDEvent{
		TimestampNs: 1,
		PID:         42,
		FD:          7,
		Op:          FDOpOpen,
	}
	copy(want.Comm[:], "leakr")

	data := encode(t, &want)
	got, err := DecodeFDEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Op != FDOpOpen {
		t.Errorf("Op = %v, want open", got.Op)
	}
	if got.Op.String() != "open" {
		t.Errorf("Op.String() = %q, want open", got.Op.String())
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
	if !IsSyscallError(0xFFFFFFF5) { // -EAGAIN
		t.Error("-EAGAIN (0xFFFFFFF5) should be an error")
	}
	if !IsSyscallError(0xFFFFFFFF) { // -EPERM
		t.Error("-EPERM should be an error")
	}
}

// silenceUnused exists to keep imports referenced when the file is read
// piecemeal; it's a no-op assertion.
var _ = net.IPv4(0, 0, 0, 0)
