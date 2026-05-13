// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package metrics defines and registers the Prometheus metrics for Kerno.
//
// All metrics use the "kerno_" namespace prefix. The package exposes typed
// metric variables that event consumers (the bridge in collector.go) can
// update directly. A dedicated custom registry is used so that the default
// Go process metrics are excluded — only Kerno metrics are exposed.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Namespace is the common prefix for all Kerno Prometheus metrics.
const Namespace = "kerno"

// Registry is a dedicated Prometheus registry for Kerno metrics.
// Using a custom registry avoids polluting the global default registry
// and gives us precise control over what /metrics exposes.
var Registry = prometheus.NewRegistry()

// ─── Syscall Metrics ──────────────────────────────────────────────────────

// SyscallDuration tracks syscall latency distributions.
var SyscallDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Namespace:  Namespace,
	Name:       "syscall_duration_nanoseconds",
	Help:       "Latency of traced syscalls in nanoseconds.",
	Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.01, 0.99: 0.001},
}, []string{"syscall", "process"})

// SyscallTotal counts the total number of syscall events observed.
var SyscallTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "syscall_total",
	Help:      "Total number of traced syscall events.",
}, []string{"syscall", "process"})

// ─── TCP Metrics ──────────────────────────────────────────────────────────

// TCPRTT tracks TCP round-trip time distributions.
var TCPRTT = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Namespace:  Namespace,
	Name:       "tcp_rtt_nanoseconds",
	Help:       "TCP round-trip time in nanoseconds.",
	Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.01, 0.99: 0.001},
}, []string{"src", "dst", "process"})

// TCPRetransmitsTotal counts TCP retransmissions.
var TCPRetransmitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "tcp_retransmits_total",
	Help:      "Total TCP retransmissions observed.",
}, []string{"src", "dst", "process"})

// TCPConnectionsTotal counts TCP connection events.
var TCPConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "tcp_connections_total",
	Help:      "Total TCP connection events observed.",
}, []string{"src", "dst", "process"})

// ─── OOM Metrics ──────────────────────────────────────────────────────────

// OOMKillsTotal counts the number of OOM kill events.
var OOMKillsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "oom_kills_total",
	Help:      "Total OOM kill events observed.",
}, []string{"process"})

// ─── Disk I/O Metrics ─────────────────────────────────────────────────────

// DiskIODuration tracks disk I/O latency distributions.
var DiskIODuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Namespace:  Namespace,
	Name:       "disk_io_duration_nanoseconds",
	Help:       "Disk I/O operation latency in nanoseconds.",
	Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.01, 0.99: 0.001},
}, []string{"device", "operation"})

// DiskIOBytesTotal tracks total bytes processed by disk I/O operations.
var DiskIOBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "disk_io_bytes_total",
	Help:      "Total bytes processed by disk I/O operations.",
}, []string{"device", "operation"})

// ─── Scheduler Metrics ────────────────────────────────────────────────────

// SchedDelay tracks CPU run queue delay distributions.
var SchedDelay = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Namespace:  Namespace,
	Name:       "sched_delay_nanoseconds",
	Help:       "CPU run queue scheduling delay in nanoseconds.",
	Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.01, 0.99: 0.001},
}, []string{"process"})

// ─── FD Metrics ───────────────────────────────────────────────────────────

// FDOpenTotal tracks the total number of file descriptor opens.
var FDOpenTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "fd_open_total",
	Help:      "Total file descriptor open operations.",
}, []string{"process"})

// FDCloseTotal tracks the total number of file descriptor closes.
var FDCloseTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "fd_close_total",
	Help:      "Total file descriptor close operations.",
}, []string{"process"})

// ─── Cgroup Memory Metrics ────────────────────────────────────────────────

// CgroupMemoryPressurePct tracks per-container memory usage as a percentage
// of the cgroup memory limit. Labeled by pod only; namespace label will be
// added once the Kubernetes enrichment path lands end-to-end.
var CgroupMemoryPressurePct = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: Namespace,
	Name:      "cgroup_memory_pressure_pct",
	Help:      "Per-container memory usage as a percentage of the cgroup memory.max limit.",
}, []string{"pod"})

// ─── Self-Monitoring Metrics ──────────────────────────────────────────────

// CollectorEventsTotal counts events processed per collector.
var CollectorEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "collector_events_total",
	Help:      "Total events processed per collector.",
}, []string{"collector"})

// CollectorErrorsTotal counts event processing errors per collector.
var CollectorErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "collector_errors_total",
	Help:      "Total event processing errors per collector.",
}, []string{"collector"})

// BPFProgramsLoaded tracks the number of successfully loaded eBPF programs.
var BPFProgramsLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: Namespace,
	Name:      "bpf_programs_loaded",
	Help:      "Number of eBPF programs currently loaded.",
})

// InfoMetric provides build/version info as labels.
var InfoMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: Namespace,
	Name:      "info",
	Help:      "Kerno build information.",
}, []string{"version"})

func init() {
	Registry.MustRegister(
		// Syscall
		SyscallDuration,
		SyscallTotal,
		// TCP
		TCPRTT,
		TCPRetransmitsTotal,
		TCPConnectionsTotal,
		// OOM
		OOMKillsTotal,
		// Disk I/O
		DiskIODuration,
		DiskIOBytesTotal,
		// Scheduler
		SchedDelay,
		// FD
		FDOpenTotal,
		FDCloseTotal,
		// Cgroup memory
		CgroupMemoryPressurePct,
		// Self-monitoring
		CollectorEventsTotal,
		CollectorErrorsTotal,
		BPFProgramsLoaded,
		InfoMetric,
	)
}
