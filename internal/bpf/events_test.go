// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

// ─── nullTermString ─────────────────────────────────────────────────────────

func TestNullTermString(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"null only", []byte{0}, ""},
		{"no null", []byte("hello"), "hello"},
		{"with null", []byte{'h', 'i', 0, 'z'}, "hi"},
		{"leading null", []byte{0, 'z'}, ""},
		{"full comm", func() []byte {
			b := [TaskCommLen]byte{}
			copy(b[:], "kerno-daemon")
			return b[:]
		}(), "kerno-daemon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nullTermString(tt.in)
			if got != tt.want {
				t.Errorf("nullTermString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ─── SyscallEvent ───────────────────────────────────────────────────────────

func TestSyscallEventBinaryRoundTrip(t *testing.T) {
	orig := SyscallEvent{
		TimestampNs: 1234567890,
		LatencyNs:   42000,
		CgroupID:    99,
		PID:         1234,
		TID:         1235,
		SyscallNr:   1, // write
		Ret:         0,
	}
	copy(orig.Comm[:], "test-proc")

	buf := marshalLE(t, &orig)
	var decoded SyscallEvent
	unmarshalLE(t, buf, &decoded)

	if decoded != orig {
		t.Errorf("round trip failed:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestSyscallEventCommString(t *testing.T) {
	e := SyscallEvent{}
	copy(e.Comm[:], "my-service")
	if got := e.CommString(); got != "my-service" {
		t.Errorf("CommString() = %q, want %q", got, "my-service")
	}
}

func TestSyscallEventLatency(t *testing.T) {
	e := SyscallEvent{LatencyNs: 5_000_000}
	if got := e.Latency(); got != 5*time.Millisecond {
		t.Errorf("Latency() = %v, want %v", got, 5*time.Millisecond)
	}
}

// ─── TCPEvent ───────────────────────────────────────────────────────────────

func TestTCPEventBinaryRoundTrip(t *testing.T) {
	orig := TCPEvent{
		TimestampNs: 9876543210,
		CgroupID:    5,
		PID:         4321,
		SAddr:       ipToUint32(t, "10.0.0.1"),
		DAddr:       ipToUint32(t, "10.0.0.2"),
		SPort:       8080,
		DPort:       443,
		Family:      2, // AF_INET
		EventType:   TCPEventRetransmit,
		State:       1,
		RTTUs:       1500,
		Retransmits: 3,
	}
	copy(orig.Comm[:], "nginx")

	buf := marshalLE(t, &orig)
	var decoded TCPEvent
	unmarshalLE(t, buf, &decoded)

	if decoded != orig {
		t.Errorf("round trip failed:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestTCPEventSrcDstAddr(t *testing.T) {
	e := TCPEvent{
		SAddr: ipToUint32(t, "192.168.1.100"),
		DAddr: ipToUint32(t, "10.0.0.1"),
	}

	if got := e.SrcAddr().String(); got != "192.168.1.100" {
		t.Errorf("SrcAddr() = %q, want %q", got, "192.168.1.100")
	}
	if got := e.DstAddr().String(); got != "10.0.0.1" {
		t.Errorf("DstAddr() = %q, want %q", got, "10.0.0.1")
	}
}

func TestTCPEventRTT(t *testing.T) {
	e := TCPEvent{RTTUs: 1500}
	want := 1500 * time.Microsecond
	if got := e.RTT(); got != want {
		t.Errorf("RTT() = %v, want %v", got, want)
	}
}

func TestTCPEventTypeString(t *testing.T) {
	tests := []struct {
		et   TCPEventType
		want string
	}{
		{TCPEventConnect, "connect"},
		{TCPEventClose, "close"},
		{TCPEventRetransmit, "retransmit"},
		{TCPEventRTT, "rtt"},
		{TCPEventType(99), "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.et.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ─── OOMEvent ───────────────────────────────────────────────────────────────

func TestOOMEventBinaryRoundTrip(t *testing.T) {
	orig := OOMEvent{
		TimestampNs:  111222333,
		CgroupID:     7,
		TotalPages:   262144,
		RSSPages:     131072,
		PID:          555,
		TriggeredPID: 556,
		OOMScore:     -17,
	}
	copy(orig.Comm[:], "oom-victim")

	buf := marshalLE(t, &orig)
	var decoded OOMEvent
	unmarshalLE(t, buf, &decoded)

	if decoded != orig {
		t.Errorf("round trip failed:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

// ─── DiskEvent ──────────────────────────────────────────────────────────────

func TestDiskEventBinaryRoundTrip(t *testing.T) {
	orig := DiskEvent{
		TimestampNs: 444555666,
		LatencyNs:   250_000,
		Sector:      1024,
		Dev:         0x800,
		NrBytes:     4096,
		Op:          'W',
	}

	buf := marshalLE(t, &orig)
	var decoded DiskEvent
	unmarshalLE(t, buf, &decoded)

	if decoded != orig {
		t.Errorf("round trip failed:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestDiskEventOpString(t *testing.T) {
	tests := []struct {
		op   byte
		want string
	}{
		{'R', "read"},
		{'W', "write"},
		{'S', "sync"},
		{'?', fmt.Sprintf("unknown(%c)", '?')},
	}
	for _, tt := range tests {
		e := DiskEvent{Op: tt.op}
		if got := e.OpString(); got != tt.want {
			t.Errorf("OpString(%c) = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestDiskEventLatency(t *testing.T) {
	e := DiskEvent{LatencyNs: 1_000_000}
	if got := e.Latency(); got != time.Millisecond {
		t.Errorf("Latency() = %v, want %v", got, time.Millisecond)
	}
}

// ─── SchedEvent ─────────────────────────────────────────────────────────────

func TestSchedEventBinaryRoundTrip(t *testing.T) {
	orig := SchedEvent{
		TimestampNs: 777888999,
		RunqDelayNs: 15_000_000,
		CgroupID:    3,
		PID:         999,
		CPU:         4,
	}
	copy(orig.Comm[:], "worker")

	buf := marshalLE(t, &orig)
	var decoded SchedEvent
	unmarshalLE(t, buf, &decoded)

	if decoded != orig {
		t.Errorf("round trip failed:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestSchedEventRunqDelay(t *testing.T) {
	e := SchedEvent{RunqDelayNs: 15_000_000}
	if got := e.RunqDelay(); got != 15*time.Millisecond {
		t.Errorf("RunqDelay() = %v, want %v", got, 15*time.Millisecond)
	}
}

// ─── FDEvent ────────────────────────────────────────────────────────────────

func TestFDEventBinaryRoundTrip(t *testing.T) {
	orig := FDEvent{
		TimestampNs: 101010101,
		CgroupID:    2,
		PID:         777,
		FD:          42,
		Op:          FDOpOpen,
	}
	copy(orig.Comm[:], "leaky-app")

	buf := marshalLE(t, &orig)
	var decoded FDEvent
	unmarshalLE(t, buf, &decoded)

	if decoded != orig {
		t.Errorf("round trip failed:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestFDOpString(t *testing.T) {
	tests := []struct {
		op   FDOp
		want string
	}{
		{FDOpOpen, "open"},
		{FDOpClose, "close"},
		{FDOp(99), "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.op.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ─── FileEvent ──────────────────────────────────────────────────────────────

func TestFileEventBinaryRoundTrip(t *testing.T) {
	orig := FileEvent{
		TimestampNs: 222333444,
		CgroupID:    10,
		PID:         500,
		UID:         1000,
		Flags:       0x42,
	}
	copy(orig.Comm[:], "cat")
	copy(orig.Filename[:], "/etc/passwd")

	buf := marshalLE(t, &orig)
	var decoded FileEvent
	unmarshalLE(t, buf, &decoded)

	if decoded != orig {
		t.Errorf("round trip failed:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestFileEventStrings(t *testing.T) {
	e := FileEvent{}
	copy(e.Comm[:], "editor")
	copy(e.Filename[:], "/tmp/test.txt")

	if got := e.CommString(); got != "editor" {
		t.Errorf("CommString() = %q, want %q", got, "editor")
	}
	if got := e.FilenameString(); got != "/tmp/test.txt" {
		t.Errorf("FilenameString() = %q, want %q", got, "/tmp/test.txt")
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// marshalLE serializes v into a byte slice using little-endian encoding.
func marshalLE(t *testing.T, v interface{}) []byte {
	t.Helper()
	size := binary.Size(v)
	if size < 0 {
		t.Fatalf("binary.Size returned -1 for %T", v)
	}
	buf := make([]byte, size)
	n, err := binary.Encode(buf, binary.LittleEndian, v)
	if err != nil {
		t.Fatalf("binary.Encode(%T): %v", v, err)
	}
	return buf[:n]
}

// unmarshalLE deserializes buf into v using little-endian encoding.
func unmarshalLE(t *testing.T, buf []byte, v interface{}) {
	t.Helper()
	_, err := binary.Decode(buf, binary.LittleEndian, v)
	if err != nil {
		t.Fatalf("binary.Decode(%T): %v", v, err)
	}
}

// ipToUint32 converts a dotted-decimal IP string to a uint32 in network byte order
// (big-endian), matching the kernel representation in our eBPF events.
func ipToUint32(t *testing.T, s string) uint32 {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid IP: %s", s)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		t.Fatalf("not an IPv4 address: %s", s)
	}
	return binary.BigEndian.Uint32(ip4)
}
