// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"time"
)

// Signals is the combined snapshot from all collectors at a point in time.
// This is the single struct that the doctor engine, exporters, and dashboard
// all consume. It provides a holistic view of kernel health.
type Signals struct {
	// Timestamp is when this snapshot was taken.
	Timestamp time.Time `json:"timestamp"`

	// Duration is the analysis window (e.g., 30s for doctor).
	Duration time.Duration `json:"duration"`

	// Host contains basic host identification.
	Host HostInfo `json:"host"`

	// Per-signal snapshots (nil if collector is disabled or has no data).
	Syscall      *SyscallSnapshot      `json:"syscall,omitempty"`
	TCP          *TCPSnapshot          `json:"tcp,omitempty"`
	OOM          *OOMSnapshot          `json:"oom,omitempty"`
	DiskIO       *DiskIOSnapshot       `json:"diskIO,omitempty"`
	Sched        *SchedSnapshot        `json:"sched,omitempty"`
	FD           *FDSnapshot           `json:"fd,omitempty"`
	Memory       *MemorySnapshot       `json:"memory,omitempty"`
	CgroupMemory *CgroupMemorySnapshot `json:"cgroupMemory,omitempty"`
}

// HostInfo identifies the machine being observed.
type HostInfo struct {
	Hostname  string `json:"hostname"`
	KernelVer string `json:"kernelVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// ─── Percentiles ────────────────────────────────────────────────────────────

// Percentiles holds common latency distribution values.
type Percentiles struct {
	P50 time.Duration `json:"p50"`
	P95 time.Duration `json:"p95"`
	P99 time.Duration `json:"p99"`
	Max time.Duration `json:"max"`
}

// ─── Syscall Snapshot ───────────────────────────────────────────────────────

// SyscallSnapshot is an aggregated view of syscall latencies over a window.
type SyscallSnapshot struct {
	// Entries keyed by (syscall_nr, comm).
	Entries []SyscallEntry `json:"entries"`

	// TotalCount is the total number of syscall events observed.
	TotalCount uint64 `json:"totalCount"`
}

// SyscallEntry represents latency stats for one (syscall, process) pair.
type SyscallEntry struct {
	SyscallNr  uint32      `json:"syscallNr"`
	Name       string      `json:"name"` // resolved syscall name
	Comm       string      `json:"comm"`
	Count      uint64      `json:"count"`
	ErrorCount uint64      `json:"errorCount"` // syscalls that returned error
	Latency    Percentiles `json:"latency"`
}

// ─── TCP Snapshot ───────────────────────────────────────────────────────────

// TCPSnapshot is an aggregated view of TCP connection health over a window.
type TCPSnapshot struct {
	// Connections tracked during the window.
	ActiveConnections int `json:"activeConnections"`

	// Retransmit statistics.
	TotalRetransmits uint64  `json:"totalRetransmits"`
	RetransmitRate   float64 `json:"retransmitRate"` // percentage

	// RTT distribution across all connections.
	RTT Percentiles `json:"rtt"`

	// Top connections by retransmit count.
	TopRetransmitters []TCPConnectionEntry `json:"topRetransmitters,omitempty"`
}

// TCPConnectionEntry represents stats for a single TCP 4-tuple.
type TCPConnectionEntry struct {
	SrcAddr     string        `json:"srcAddr"`
	DstAddr     string        `json:"dstAddr"`
	SrcPort     uint16        `json:"srcPort"`
	DstPort     uint16        `json:"dstPort"`
	Comm        string        `json:"comm"`
	RTT         time.Duration `json:"rtt"`
	Retransmits uint32        `json:"retransmits"`
}

// ─── OOM Snapshot ───────────────────────────────────────────────────────────

// OOMSnapshot contains OOM kill events observed during the window.
// Every OOM event is captured — no aggregation (each one is critical).
type OOMSnapshot struct {
	Events []OOMEventEntry `json:"events"`
	Count  int             `json:"count"`
}

// OOMEventEntry is a single OOM kill event.
type OOMEventEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	PID          uint32    `json:"pid"`
	Comm         string    `json:"comm"`
	TriggeredPID uint32    `json:"triggeredPid"`
	TotalPages   uint64    `json:"totalPages"`
	RSSPages     uint64    `json:"rssPages"`
	OOMScore     int32     `json:"oomScore"`
	CgroupID     uint64    `json:"cgroupId"`
}

// ─── Disk I/O Snapshot ──────────────────────────────────────────────────────

// DiskIOSnapshot is an aggregated view of block I/O latencies over a window.
type DiskIOSnapshot struct {
	// Per-operation latency distributions.
	ReadLatency  Percentiles `json:"readLatency"`
	WriteLatency Percentiles `json:"writeLatency"`
	SyncLatency  Percentiles `json:"syncLatency"`

	// Counts.
	TotalReads  uint64 `json:"totalReads"`
	TotalWrites uint64 `json:"totalWrites"`
	TotalSyncs  uint64 `json:"totalSyncs"`

	// Throughput.
	ReadBytes  uint64 `json:"readBytes"`
	WriteBytes uint64 `json:"writeBytes"`
}

// ─── Scheduler Snapshot ─────────────────────────────────────────────────────

// SchedSnapshot is an aggregated view of CPU run queue delays over a window.
type SchedSnapshot struct {
	// Global run queue delay distribution.
	RunqDelay Percentiles `json:"runqDelay"`

	// Per-process entries with highest delays.
	TopDelayed []SchedEntry `json:"topDelayed,omitempty"`

	// TotalCount is the total number of scheduling events observed.
	TotalCount uint64 `json:"totalCount"`
}

// SchedEntry represents scheduling stats for one process.
type SchedEntry struct {
	PID       uint32      `json:"pid"`
	Comm      string      `json:"comm"`
	Count     uint64      `json:"count"`
	RunqDelay Percentiles `json:"runqDelay"`
}

// ─── FD Snapshot ────────────────────────────────────────────────────────────

// FDSnapshot tracks file descriptor open/close rates to detect leaks.
type FDSnapshot struct {
	// Per-PID FD tracking.
	Entries []FDEntry `json:"entries,omitempty"`

	// Global counters.
	TotalOpens  uint64  `json:"totalOpens"`
	TotalCloses uint64  `json:"totalCloses"`
	NetDelta    int64   `json:"netDelta"`   // opens - closes
	GrowthRate  float64 `json:"growthRate"` // FDs per second

	// TopPIDCurrentFDs is the actual open-fd count of the top leaker, read from /proc/<pid>/fd.
	// 0 means it was not available (process exited, permission denied, etc.).
	TopPIDCurrentFDs int `json:"topPidCurrentFDs,omitempty"`
}

// FDEntry represents FD stats for one process.
type FDEntry struct {
	PID        uint32  `json:"pid"`
	Comm       string  `json:"comm"`
	Opens      uint64  `json:"opens"`
	Closes     uint64  `json:"closes"`
	NetDelta   int64   `json:"netDelta"`
	GrowthRate float64 `json:"growthRate"` // FDs per second

	// CurrentFDs is the live fd count read from /proc/<pid>/fd at snapshot time. 0 = unavailable.
	CurrentFDs int `json:"currentFDs,omitempty"`
	// FDLimit is the soft RLIMIT_NOFILE for this PID read from /proc/<pid>/limits. 0 = unavailable.
	FDLimit int `json:"fdLimit,omitempty"`
}

// ─── Cgroup Memory Snapshot ──────────────────────────────────────────────────

// CgroupMemorySnapshot holds per-container cgroup v2 memory state, populated
// by the CgroupMemoryCollector. On systems without cgroup v2 limits this will
// be nil or contain an empty Containers slice.
type CgroupMemorySnapshot struct {
	Containers []CgroupMemoryEntry `json:"containers"`
}

// CgroupMemoryEntry is the memory state for a single cgroup (container).
type CgroupMemoryEntry struct {
	// CgroupPath is the absolute path of the cgroup directory.
	CgroupPath string `json:"cgroupPath"`
	// Pod is the pod name or UID extracted from the cgroup path.
	Pod string `json:"pod"`
	// Namespace is the Kubernetes namespace (empty when enrichment is not available).
	Namespace string `json:"namespace"`

	// CurrentBytes is the value of memory.current.
	CurrentBytes uint64 `json:"currentBytes"`
	// LimitBytes is the value of memory.max.
	LimitBytes uint64 `json:"limitBytes"`
	// HighBytes is the value of memory.high (0 = not set).
	HighBytes uint64 `json:"highBytes"`
	// UsedPct is CurrentBytes / LimitBytes * 100.
	UsedPct float64 `json:"usedPct"`

	// GrowthRateBytesPerSec is the rate of change of CurrentBytes between polls.
	GrowthRateBytesPerSec float64 `json:"growthRateBytesPerSec"`
	// HighEventRate is the rate of memory.events.high increments per second.
	HighEventRate float64 `json:"highEventRate"`

	// Event counters from memory.events.
	EventsHigh    uint64 `json:"eventsHigh"`
	EventsMax     uint64 `json:"eventsMax"`
	EventsOOM     uint64 `json:"eventsOOM"`
	EventsOOMKill uint64 `json:"eventsOOMKill"`
}

// ─── Memory Snapshot ─────────────────────────────────────────────────────────

// MemorySnapshot tracks system memory usage and pressure.
type MemorySnapshot struct {
	// TotalBytes is total system memory.
	TotalBytes uint64 `json:"totalBytes"`

	// UsedBytes is current memory in use (excluding caches/buffers).
	UsedBytes uint64 `json:"usedBytes"`

	// UsedPct is the percentage of memory in use (0–100).
	UsedPct float64 `json:"usedPct"`

	// GrowthRateBytesPerSec is the rate of memory consumption growth.
	GrowthRateBytesPerSec float64 `json:"growthRateBytesPerSec"`

	// AvailableBytes is memory available for allocation without swapping.
	AvailableBytes uint64 `json:"availableBytes"`

	// SwapUsedBytes is current swap usage.
	SwapUsedBytes uint64 `json:"swapUsedBytes"`

	// SwapTotalBytes is total swap space.
	SwapTotalBytes uint64 `json:"swapTotalBytes"`
}
