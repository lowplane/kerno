// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// TaskCommLen matches TASK_COMM_LEN in kerno.h.
const TaskCommLen = 16

// MaxFilenameLen matches MAX_FILENAME_LEN in kerno.h.
const MaxFilenameLen = 256

// ─── Syscall Latency Event ─────────────────────────────────────────────────

// SyscallEvent matches struct syscall_event in kerno.h.
// Field order and sizes MUST be identical to the C struct.
type SyscallEvent struct {
	TimestampNs uint64
	LatencyNs   uint64
	CgroupID    uint64
	PID         uint32
	TID         uint32
	SyscallNr   uint32
	Ret         uint32
	Comm        [TaskCommLen]byte
}

// CommString returns the process name as a Go string.
func (e *SyscallEvent) CommString() string {
	return nullTermString(e.Comm[:])
}

// Latency returns the syscall latency as a time.Duration.
func (e *SyscallEvent) Latency() time.Duration {
	return time.Duration(e.LatencyNs)
}

// ─── TCP Monitor Event ─────────────────────────────────────────────────────

// TCPEventType is the subtype of a TCP event.
type TCPEventType uint8

const (
	TCPEventConnect    TCPEventType = 1
	TCPEventClose      TCPEventType = 2
	TCPEventRetransmit TCPEventType = 3
	TCPEventRTT        TCPEventType = 4
)

// String returns a human-readable name.
func (t TCPEventType) String() string {
	switch t {
	case TCPEventConnect:
		return "connect"
	case TCPEventClose:
		return "close"
	case TCPEventRetransmit:
		return "retransmit"
	case TCPEventRTT:
		return "rtt"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// TCPEvent matches struct tcp_event in kerno.h.
type TCPEvent struct {
	TimestampNs uint64
	CgroupID    uint64
	PID         uint32
	SAddr       uint32 // network byte order
	DAddr       uint32 // network byte order
	SPort       uint16
	DPort       uint16
	Family      uint16
	EventType   TCPEventType
	State       uint8
	RTTUs       uint32
	Retransmits uint32
	Comm        [TaskCommLen]byte
}

// CommString returns the process name as a Go string.
func (e *TCPEvent) CommString() string {
	return nullTermString(e.Comm[:])
}

// SrcAddr returns the source IP address.
func (e *TCPEvent) SrcAddr() net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.SAddr)
	return ip
}

// DstAddr returns the destination IP address.
func (e *TCPEvent) DstAddr() net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.DAddr)
	return ip
}

// RTT returns the round-trip time as a time.Duration.
func (e *TCPEvent) RTT() time.Duration {
	return time.Duration(e.RTTUs) * time.Microsecond
}

// ─── OOM Kill Event ────────────────────────────────────────────────────────

// OOMEvent matches struct oom_event in kerno.h.
type OOMEvent struct {
	TimestampNs  uint64
	CgroupID     uint64
	TotalPages   uint64
	RSSPages     uint64
	PID          uint32
	TriggeredPID uint32
	OOMScore     int32
	Pad0         uint32 // padding to align Comm
	Comm         [TaskCommLen]byte
}

// CommString returns the victim process name.
func (e *OOMEvent) CommString() string {
	return nullTermString(e.Comm[:])
}

// ─── Disk I/O Event ────────────────────────────────────────────────────────

// DiskEvent matches struct disk_event in kerno.h.
type DiskEvent struct {
	TimestampNs uint64
	LatencyNs   uint64
	Sector      uint64
	Dev         uint32
	NrBytes     uint32
	Op          byte
	Pad0        [7]byte // padding to 8-byte alignment
}

// Latency returns the I/O latency as a time.Duration.
func (e *DiskEvent) Latency() time.Duration {
	return time.Duration(e.LatencyNs)
}

// OpString returns a human-readable operation type.
func (e *DiskEvent) OpString() string {
	switch e.Op {
	case 'R':
		return "read"
	case 'W':
		return "write"
	case 'S':
		return "sync"
	default:
		return fmt.Sprintf("unknown(%c)", e.Op)
	}
}

// ─── Scheduler Delay Event ─────────────────────────────────────────────────

// SchedEvent matches struct sched_event in kerno.h.
type SchedEvent struct {
	TimestampNs  uint64
	RunqDelayNs  uint64
	CgroupID     uint64
	PID          uint32
	CPU          uint32
	Comm         [TaskCommLen]byte
}

// CommString returns the process name.
func (e *SchedEvent) CommString() string {
	return nullTermString(e.Comm[:])
}

// RunqDelay returns the run queue delay as a time.Duration.
func (e *SchedEvent) RunqDelay() time.Duration {
	return time.Duration(e.RunqDelayNs)
}

// ─── File Descriptor Track Event ───────────────────────────────────────────

// FDOp is the type of file descriptor operation.
type FDOp uint8

const (
	FDOpOpen  FDOp = 1
	FDOpClose FDOp = 2
)

// String returns a human-readable name.
func (o FDOp) String() string {
	switch o {
	case FDOpOpen:
		return "open"
	case FDOpClose:
		return "close"
	default:
		return fmt.Sprintf("unknown(%d)", o)
	}
}

// FDEvent matches struct fd_event in kerno.h.
type FDEvent struct {
	TimestampNs uint64
	CgroupID    uint64
	PID         uint32
	FD          int32
	Op          FDOp
	Pad0        [7]byte // padding to align Comm
	Comm        [TaskCommLen]byte
}

// CommString returns the process name.
func (e *FDEvent) CommString() string {
	return nullTermString(e.Comm[:])
}

// ─── File Audit Event ──────────────────────────────────────────────────────

// FileEvent matches struct file_event in kerno.h.
type FileEvent struct {
	TimestampNs uint64
	CgroupID    uint64
	PID         uint32
	UID         uint32
	Flags       uint32
	Pad0        uint32 // padding to 8-byte alignment
	Comm        [TaskCommLen]byte
	Filename    [MaxFilenameLen]byte
}

// CommString returns the process name.
func (e *FileEvent) CommString() string {
	return nullTermString(e.Comm[:])
}

// FilenameString returns the filename.
func (e *FileEvent) FilenameString() string {
	return nullTermString(e.Filename[:])
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// nullTermString converts a null-terminated byte slice to a Go string.
func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
