// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"time"
)

// Signals is the combined snapshot from all collectors at a point in time.
type Signals struct {
	Timestamp    time.Time             `json:"timestamp"`
	Duration     time.Duration         `json:"duration"`
	Host         HostInfo              `json:"host"`
	Syscall      *SyscallSnapshot      `json:"syscall,omitempty"`
	TCP          *TCPSnapshot          `json:"tcp,omitempty"`
	OOM          *OOMSnapshot          `json:"oom,omitempty"`
	DiskIO       *DiskIOSnapshot       `json:"diskIO,omitempty"`
	Sched        *SchedSnapshot        `json:"sched,omitempty"`
	FD           *FDSnapshot           `json:"fd,omitempty"`
	Memory       *MemorySnapshot       `json:"memory,omitempty"`
	CgroupMemory *CgroupMemorySnapshot `json:"cgroupMemory,omitempty"`
	DNS          *DNSSnapshot          `json:"dns,omitempty"`
}

// HostInfo identifies the machine being observed.
type HostInfo struct {
	Hostname  string `json:"hostname"`
	KernelVer string `json:"kernelVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Percentiles holds common latency distribution values.
type Percentiles struct {
	P50 time.Duration `json:"p50"`
	P95 time.Duration `json:"p95"`
	P99 time.Duration `json:"p99"`
	Max time.Duration `json:"max"`
}

// SyscallSnapshot is an aggregated view of syscall latencies over a window.
type SyscallSnapshot struct {
	Entries    []SyscallEntry `json:"entries"`
	TotalCount uint64         `json:"totalCount"`
}

type SyscallEntry struct {
	SyscallNr  uint32      `json:"syscallNr"`
	Name       string      `json:"name"`
	Comm       string      `json:"comm"`
	Count      uint64      `json:"count"`
	ErrorCount uint64      `json:"errorCount"`
	Latency    Percentiles `json:"latency"`
}

// TCPSnapshot is an aggregated view of TCP connection health over a window.
type TCPSnapshot struct {
	ActiveConnections int                  `json:"activeConnections"`
	TotalRetransmits  uint64               `json:"totalRetransmits"`
	RetransmitRate    float64              `json:"retransmitRate"`
	RTT               Percentiles          `json:"rtt"`
	TopRetransmitters []TCPConnectionEntry `json:"topRetransmitters,omitempty"`
}

type TCPConnectionEntry struct {
	SrcAddr     string        `json:"srcAddr"`
	DstAddr     string        `json:"dstAddr"`
	SrcPort     uint16        `json:"srcPort"`
	DstPort     uint16        `json:"dstPort"`
	Comm        string        `json:"comm"`
	RTT         time.Duration `json:"rtt"`
	Retransmits uint32        `json:"retransmits"`
}

// OOMSnapshot contains OOM kill events observed during the window.
type OOMSnapshot struct {
	Events []OOMEventEntry `json:"events"`
	Count  int             `json:"count"`
}

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

// DiskIOSnapshot is an aggregated view of block I/O latencies over a window.
type DiskIOSnapshot struct {
	ReadLatency  Percentiles `json:"readLatency"`
	WriteLatency Percentiles `json:"writeLatency"`
	SyncLatency  Percentiles `json:"syncLatency"`
	TotalReads   uint64      `json:"totalReads"`
	TotalWrites  uint64      `json:"totalWrites"`
	TotalSyncs   uint64      `json:"totalSyncs"`
	ReadBytes    uint64      `json:"readBytes"`
	WriteBytes   uint64      `json:"writeBytes"`
}

// SchedSnapshot is an aggregated view of CPU run queue delays over a window.
type SchedSnapshot struct {
	RunqDelay  Percentiles  `json:"runqDelay"`
	TopDelayed []SchedEntry `json:"topDelayed,omitempty"`
	TotalCount uint64       `json:"totalCount"`
}

type SchedEntry struct {
	PID       uint32      `json:"pid"`
	Comm      string      `json:"comm"`
	Count     uint64      `json:"count"`
	RunqDelay Percentiles `json:"runqDelay"`
}

// FDSnapshot tracks file descriptor open/close rates to detect leaks.
type FDSnapshot struct {
	Entries     []FDEntry `json:"entries,omitempty"`
	TotalOpens  uint64    `json:"totalOpens"`
	TotalCloses uint64    `json:"totalCloses"`
	NetDelta    int64     `json:"netDelta"`
	GrowthRate  float64   `json:"growthRate"`
}

type FDEntry struct {
	PID        uint32  `json:"pid"`
	Comm       string  `json:"comm"`
	Opens      uint64  `json:"opens"`
	Closes     uint64  `json:"closes"`
	NetDelta   int64   `json:"netDelta"`
	GrowthRate float64 `json:"growthRate"`
}

// CgroupMemorySnapshot holds per-container cgroup v2 memory state.
type CgroupMemorySnapshot struct {
	Containers []CgroupMemoryEntry `json:"containers"`
}

type CgroupMemoryEntry struct {
	CgroupPath            string  `json:"cgroupPath"`
	Pod                   string  `json:"pod"`
	Namespace             string  `json:"namespace"`
	CurrentBytes          uint64  `json:"currentBytes"`
	LimitBytes            uint64  `json:"limitBytes"`
	HighBytes             uint64  `json:"highBytes"`
	UsedPct               float64 `json:"usedPct"`
	GrowthRateBytesPerSec float64 `json:"growthRateBytesPerSec"`
	HighEventRate         float64 `json:"highEventRate"`
	EventsHigh            uint64  `json:"eventsHigh"`
	EventsMax             uint64  `json:"eventsMax"`
	EventsOOM             uint64  `json:"eventsOOM"`
	EventsOOMKill         uint64  `json:"eventsOOMKill"`
}

// DNSSnapshot is an aggregated view of DNS query health over a window.
type DNSSnapshot struct {
	RequestRate    float64            `json:"requestRate"`
	ResponseRate   float64            `json:"responseRate"`
	FailureRate    float64            `json:"failureRate"`
	TotalRequests  uint64             `json:"totalRequests"`
	TotalResponses uint64             `json:"totalResponses"`
	TotalFailures  uint64             `json:"totalFailures"`
	Latency        Percentiles        `json:"latency"`
	TopConsumers   []DNSConsumerEntry `json:"topConsumers,omitempty"`
}

type DNSConsumerEntry struct {
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Requests uint64 `json:"requests"`
	Failures uint64 `json:"failures"`
}

// MemorySnapshot tracks system memory usage and pressure.
type MemorySnapshot struct {
	TotalBytes            uint64  `json:"totalBytes"`
	UsedBytes             uint64  `json:"usedBytes"`
	UsedPct               float64 `json:"usedPct"`
	GrowthRateBytesPerSec float64 `json:"growthRateBytesPerSec"`
	AvailableBytes        uint64  `json:"availableBytes"`
	SwapUsedBytes         uint64  `json:"swapUsedBytes"`
	SwapTotalBytes        uint64  `json:"swapTotalBytes"`
}
