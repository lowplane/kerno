// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"time"

	"github.com/lowplane/kerno/internal/collector"
	"github.com/lowplane/kerno/internal/config"
)

// Evaluate runs all diagnostic rules against the collected signals and returns
// findings sorted by severity. This is the deterministic core of kerno doctor —
// no AI, no network calls, always available.
func Evaluate(signals *collector.Signals, thresholds config.DoctorThresholds) []Finding {
	var findings []Finding

	findings = append(findings, evalDiskIOBottleneck(signals, thresholds)...)
	findings = append(findings, evalOOMKillOccurred(signals)...)
	findings = append(findings, evalTCPRetransmitStorm(signals, thresholds)...)
	findings = append(findings, evalTCPRTTDegradation(signals, thresholds)...)
	findings = append(findings, evalSchedulerContention(signals, thresholds)...)
	findings = append(findings, evalFDLeak(signals, thresholds)...)
	findings = append(findings, evalSyscallLatencyHigh(signals, thresholds)...)
	findings = append(findings, evalOOMImminent(signals, thresholds)...)
	findings = append(findings, evalSyscallErrorRate(signals)...)

	// If nothing found, emit "healthy system" info.
	if len(findings) == 0 {
		findings = append(findings, evalHealthySystem(signals))
	}

	RankFindings(findings)
	return findings
}

// ── Rule 1: Disk I/O Bottleneck ─────────────────────────────────────────────

func evalDiskIOBottleneck(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.DiskIO == nil {
		return nil
	}

	var findings []Finding
	warningNs := time.Duration(t.DiskP99WarningNs)
	criticalNs := time.Duration(t.DiskP99CriticalNs)

	// Check sync latency (fsync — most impactful for databases).
	if syncP99 := s.DiskIO.SyncLatency.P99; syncP99 > 0 {
		if syncP99 >= criticalNs {
			findings = append(findings, Finding{
				Severity:  SeverityCritical,
				Rule:      "disk_io_bottleneck",
				Title:     "Disk I/O Bottleneck Detected",
				Signal:    "diskio",
				Cause:     "Storage device is saturated — sync/fsync operations are blocking",
				Impact:    "Database writes and file syncs are delayed, causing cascade latency",
				Evidence:  fmt.Sprintf("sync P99=%s (threshold: %s), %d sync ops in window", syncP99, criticalNs, s.DiskIO.TotalSyncs),
				Fix:       []string{"Check disk IOPS: iostat -x 1 5", "Check write queue depth", "Consider faster storage or async fsync"},
				Metric:    "disk_sync_p99",
				Value:     float64(syncP99.Nanoseconds()),
				Threshold: float64(criticalNs.Nanoseconds()),
			})
		} else if syncP99 >= warningNs {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Rule:      "disk_io_bottleneck",
				Title:     "Elevated Disk Sync Latency",
				Signal:    "diskio",
				Cause:     "Sync/fsync operations are slower than expected",
				Impact:    "Write-heavy workloads may experience elevated latency",
				Evidence:  fmt.Sprintf("sync P99=%s (threshold: %s), %d sync ops", syncP99, warningNs, s.DiskIO.TotalSyncs),
				Fix:       []string{"Monitor with: iostat -x 1", "Check if disk is shared with noisy workloads"},
				Metric:    "disk_sync_p99",
				Value:     float64(syncP99.Nanoseconds()),
				Threshold: float64(warningNs.Nanoseconds()),
			})
		}
	}

	// Check write latency.
	if writeP99 := s.DiskIO.WriteLatency.P99; writeP99 >= criticalNs {
		findings = append(findings, Finding{
			Severity:  SeverityCritical,
			Rule:      "disk_io_write_high",
			Title:     "Critical Disk Write Latency",
			Signal:    "diskio",
			Cause:     "Block-level write operations are critically slow",
			Impact:    "All write I/O is affected — applications may hang or timeout",
			Evidence:  fmt.Sprintf("write P99=%s (threshold: %s), %d writes", writeP99, criticalNs, s.DiskIO.TotalWrites),
			Fix:       []string{"Check device health: smartctl -a /dev/sdX", "Check for I/O scheduler issues"},
			Metric:    "disk_write_p99",
			Value:     float64(writeP99.Nanoseconds()),
			Threshold: float64(criticalNs.Nanoseconds()),
		})
	}

	return findings
}

// ── Rule 2/3: OOM Kill ──────────────────────────────────────────────────────

func evalOOMKillOccurred(s *collector.Signals) []Finding {
	if s.OOM == nil || s.OOM.Count == 0 {
		return nil
	}

	var findings []Finding
	for _, evt := range s.OOM.Events {
		findings = append(findings, Finding{
			Severity: SeverityCritical,
			Rule:     "oom_kill_occurred",
			Title:    "OOM Kill Detected",
			Signal:   "oom",
			Cause:    fmt.Sprintf("Process %s (pid %d) was killed by the OOM killer", evt.Comm, evt.PID),
			Impact:   "Process was terminated — service disruption likely",
			Evidence: fmt.Sprintf("OOM score: %d, RSS pages: %d, total pages: %d", evt.OOMScore, evt.RSSPages, evt.TotalPages),
			Fix: []string{
				fmt.Sprintf("Check memory limits for process: cat /proc/%d/cgroup", evt.PID),
				"Increase memory limit or optimize memory usage",
				"Check for memory leaks: valgrind or Go pprof",
			},
			Metric:  "oom_kills",
			Value:   1,
			Process: evt.Comm,
		})
	}

	return findings
}

// ── Rule 4: TCP Retransmit Storm ────────────────────────────────────────────

func evalTCPRetransmitStorm(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.TCP == nil {
		return nil
	}

	rate := s.TCP.RetransmitRate
	if rate < t.TCPRetransmitPct {
		return nil
	}

	f := Finding{
		Severity:  SeverityCritical,
		Rule:      "tcp_retransmit_storm",
		Title:     "TCP Retransmit Storm",
		Signal:    "tcp",
		Cause:     "Network path degradation causing excessive retransmissions",
		Impact:    fmt.Sprintf("%.1f%% of TCP segments are being retransmitted — every connection has a chance of latency spike", rate),
		Evidence:  fmt.Sprintf("retransmit rate=%.1f%% (threshold: %.1f%%), %d total retransmits, %d active connections", rate, t.TCPRetransmitPct, s.TCP.TotalRetransmits, s.TCP.ActiveConnections),
		Fix:       []string{"Check network errors: ethtool -S eth0 | grep -i error", "Check for packet loss: ping -c 100 <gateway>", "Consider pod/service placement (cross-AZ traffic)"},
		Metric:    "tcp_retransmit_pct",
		Value:     rate,
		Threshold: t.TCPRetransmitPct,
	}

	// Add top retransmitter info if available.
	if len(s.TCP.TopRetransmitters) > 0 {
		top := s.TCP.TopRetransmitters[0]
		f.Evidence += fmt.Sprintf(", top: %s:%d → %s:%d (%d retransmits)",
			top.SrcAddr, top.SrcPort, top.DstAddr, top.DstPort, top.Retransmits)
	}

	return []Finding{f}
}

// ── Rule 5: TCP RTT Degradation ─────────────────────────────────────────────

func evalTCPRTTDegradation(s *collector.Signals, _ config.DoctorThresholds) []Finding {
	if s.TCP == nil {
		return nil
	}

	// RTT p99 > 10ms is concerning.
	rttThreshold := 10 * time.Millisecond
	if s.TCP.RTT.P99 < rttThreshold {
		return nil
	}

	return []Finding{{
		Severity:  SeverityWarning,
		Rule:      "tcp_rtt_degradation",
		Title:     "Elevated TCP Round-Trip Time",
		Signal:    "tcp",
		Cause:     "Network latency is higher than expected",
		Impact:    fmt.Sprintf("Every TCP round-trip adds %s of latency — impacts all network-dependent operations", s.TCP.RTT.P99),
		Evidence:  fmt.Sprintf("RTT P99=%s, P50=%s (threshold: %s)", s.TCP.RTT.P99, s.TCP.RTT.P50, rttThreshold),
		Fix:       []string{"Check network path: traceroute <destination>", "Check for congestion: ss -ti", "Consider co-locating services to reduce hops"},
		Metric:    "tcp_rtt_p99",
		Value:     float64(s.TCP.RTT.P99.Nanoseconds()),
		Threshold: float64(rttThreshold.Nanoseconds()),
	}}
}

// ── Rule 6: Scheduler Contention ────────────────────────────────────────────

func evalSchedulerContention(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.Sched == nil {
		return nil
	}

	warningNs := time.Duration(t.SchedDelayWarningNs)
	criticalNs := time.Duration(t.SchedDelayCriticalNs)
	delay := s.Sched.RunqDelay.P99

	if delay < warningNs {
		return nil
	}

	sev := SeverityWarning
	if delay >= criticalNs {
		sev = SeverityCritical
	}

	f := Finding{
		Severity:  sev,
		Rule:      "scheduler_contention",
		Title:     "CPU Scheduler Contention",
		Signal:    "sched",
		Cause:     "Processes are waiting in the CPU run queue longer than expected",
		Impact:    fmt.Sprintf("Every context switch adds ~%s of delay — compounds with I/O latency", delay),
		Evidence:  fmt.Sprintf("runqueue P99=%s, P50=%s (warning: %s, critical: %s)", delay, s.Sched.RunqDelay.P50, warningNs, criticalNs),
		Fix:       []string{"Check CPU usage: top -H", "Consider increasing CPU count or reducing worker threads", "Check for noisy neighbors on shared nodes"},
		Metric:    "sched_runq_p99",
		Value:     float64(delay.Nanoseconds()),
		Threshold: float64(warningNs.Nanoseconds()),
	}

	// Add top delayed processes if available.
	if len(s.Sched.TopDelayed) > 0 {
		top := s.Sched.TopDelayed[0]
		f.Process = top.Comm
		f.Evidence += fmt.Sprintf(", most delayed: %s (pid %d, P99=%s)", top.Comm, top.PID, top.RunqDelay.P99)
	}

	return []Finding{f}
}

// ── Rule 7: FD Leak ─────────────────────────────────────────────────────────

func evalFDLeak(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.FD == nil {
		return nil
	}

	if s.FD.GrowthRate < t.FDGrowthPerSec {
		return nil
	}

	f := Finding{
		Severity:  SeverityWarning,
		Rule:      "fd_leak",
		Title:     "File Descriptor Leak Suspected",
		Signal:    "fd",
		Cause:     "File descriptors are being opened faster than closed",
		Impact:    "Process will eventually hit ulimit and crash",
		Evidence:  fmt.Sprintf("growth rate=%.1f FDs/sec (threshold: %.1f), opens=%d, closes=%d, net delta=%d", s.FD.GrowthRate, t.FDGrowthPerSec, s.FD.TotalOpens, s.FD.TotalCloses, s.FD.NetDelta),
		Fix:       []string{"Check open FDs: ls /proc/<pid>/fd | wc -l", "Find leak: lsof -p <pid> | head -20", "Ensure response bodies and connections are closed"},
		Metric:    "fd_growth_per_sec",
		Value:     s.FD.GrowthRate,
		Threshold: t.FDGrowthPerSec,
	}

	// Estimate time to ulimit (65536 default).
	if s.FD.GrowthRate > 0 {
		// Assume 65536 ulimit and current count based on delta.
		remainingFDs := 65536.0 - float64(s.FD.NetDelta)
		if remainingFDs > 0 {
			etaSecs := remainingFDs / s.FD.GrowthRate
			eta := time.Duration(etaSecs) * time.Second
			f.ETA = &eta
			f.Impact = fmt.Sprintf("Process will hit ulimit (65536) in %s at current growth rate", f.ETAString())
		}
	}

	// Add top leaker if available.
	if len(s.FD.Entries) > 0 {
		top := s.FD.Entries[0]
		f.Process = top.Comm
		f.Evidence += fmt.Sprintf(", top leaker: %s (pid %d, +%d net)", top.Comm, top.PID, top.NetDelta)
	}

	return []Finding{f}
}

// ── Rule 8: Syscall Latency High ────────────────────────────────────────────

func evalSyscallLatencyHigh(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.Syscall == nil {
		return nil
	}

	warningNs := time.Duration(t.SyscallP99WarningNs)
	criticalNs := time.Duration(t.SyscallP99CriticalNs)

	var findings []Finding
	for _, entry := range s.Syscall.Entries {
		p99 := entry.Latency.P99
		if p99 < warningNs {
			continue
		}

		sev := SeverityWarning
		thresh := warningNs
		if p99 >= criticalNs {
			sev = SeverityCritical
			thresh = criticalNs
		}

		name := entry.Name
		if name == "" {
			name = fmt.Sprintf("syscall_%d", entry.SyscallNr)
		}

		findings = append(findings, Finding{
			Severity:  sev,
			Rule:      "syscall_latency_high",
			Title:     fmt.Sprintf("High %s() Syscall Latency", name),
			Signal:    "syscall",
			Cause:     fmt.Sprintf("%s() P99 latency exceeds threshold", name),
			Impact:    fmt.Sprintf("Processes calling %s() experience %s latency at the 99th percentile", name, p99),
			Evidence:  fmt.Sprintf("%s() P99=%s, P50=%s, count=%d (threshold: %s)", name, p99, entry.Latency.P50, entry.Count, thresh),
			Fix:       []string{fmt.Sprintf("Profile %s() callers: strace -e trace=%s -p <pid>", name, name), "Check if underlying resource (disk, network) is saturated"},
			Metric:    fmt.Sprintf("syscall_%s_p99", name),
			Value:     float64(p99.Nanoseconds()),
			Threshold: float64(thresh.Nanoseconds()),
			Process:   entry.Comm,
		})
	}

	return findings
}

// ── Rule 9: OOM Imminent ─────────────────────────────────────────────────────

func evalOOMImminent(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.Memory == nil {
		return nil
	}

	threshold := t.OOMMemoryPct
	if threshold == 0 {
		threshold = 90.0
	}

	if s.Memory.UsedPct < threshold {
		return nil
	}

	sev := SeverityWarning
	title := "Memory Pressure — OOM Risk"

	// If memory is >95% AND growing, it's critical.
	if s.Memory.UsedPct > 95.0 && s.Memory.GrowthRateBytesPerSec > 0 {
		sev = SeverityCritical
		title = "OOM Imminent — Memory Nearly Exhausted"
	}

	f := Finding{
		Severity:  sev,
		Rule:      "oom_imminent",
		Title:     title,
		Signal:    "memory",
		Cause:     "System memory usage exceeds safe threshold and may be growing",
		Impact:    "OOM killer will start terminating processes if memory is not freed",
		Evidence:  fmt.Sprintf("memory used=%.1f%% (%s / %s), growth=%.0f bytes/sec", s.Memory.UsedPct, formatBytes(s.Memory.UsedBytes), formatBytes(s.Memory.TotalBytes), s.Memory.GrowthRateBytesPerSec),
		Fix:       []string{"Check top memory consumers: ps aux --sort=-%mem | head", "Look for memory leaks: watch -n1 'smem -t -k'", "Consider adding swap or increasing memory limit"},
		Metric:    "memory_used_pct",
		Value:     s.Memory.UsedPct,
		Threshold: threshold,
	}

	// Estimate time to 100% if growing.
	if s.Memory.GrowthRateBytesPerSec > 0 && s.Memory.AvailableBytes > 0 {
		etaSecs := float64(s.Memory.AvailableBytes) / s.Memory.GrowthRateBytesPerSec
		eta := time.Duration(etaSecs) * time.Second
		f.ETA = &eta
		f.Impact = fmt.Sprintf("At current growth rate, memory will be exhausted in %s", f.ETAString())
	}

	return []Finding{f}
}

// ── Rule 10: Syscall Error Rate ──────────────────────────────────────────────

func evalSyscallErrorRate(s *collector.Signals) []Finding {
	if s.Syscall == nil {
		return nil
	}

	var findings []Finding
	for _, entry := range s.Syscall.Entries {
		if entry.Count == 0 || entry.ErrorCount == 0 {
			continue
		}

		errorRate := float64(entry.ErrorCount) / float64(entry.Count) * 100.0
		if errorRate < 1.0 {
			continue
		}

		name := entry.Name
		if name == "" {
			name = fmt.Sprintf("syscall_%d", entry.SyscallNr)
		}

		sev := SeverityWarning
		if errorRate >= 10.0 {
			sev = SeverityCritical
		}

		findings = append(findings, Finding{
			Severity:  sev,
			Rule:      "syscall_error_rate",
			Title:     fmt.Sprintf("High %s() Error Rate", name),
			Signal:    "syscall",
			Cause:     fmt.Sprintf("%s() is failing %.1f%% of the time", name, errorRate),
			Impact:    fmt.Sprintf("%d out of %d %s() calls are returning errors", entry.ErrorCount, entry.Count, name),
			Evidence:  fmt.Sprintf("%s() error rate=%.1f%% (%d errors / %d calls)", name, errorRate, entry.ErrorCount, entry.Count),
			Fix:       []string{fmt.Sprintf("Trace errors: strace -e trace=%s -Z -p <pid>", name), "Check if the underlying resource is unavailable", "Check errno patterns: perf trace -e %s -p <pid>"},
			Metric:    fmt.Sprintf("syscall_%s_error_pct", name),
			Value:     errorRate,
			Threshold: 1.0,
			Process:   entry.Comm,
		})
	}

	return findings
}

// formatBytes returns a human-readable byte size.
func formatBytes(b uint64) string {
	const (
		kB = 1024
		mB = kB * 1024
		gB = mB * 1024
	)
	switch {
	case b >= gB:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(gB))
	case b >= mB:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(mB))
	case b >= kB:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(kB))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// ── Rule 11: Healthy System ─────────────────────────────────────────────────

func evalHealthySystem(s *collector.Signals) Finding {
	evidence := "All kernel signals within normal thresholds"
	if s.Syscall != nil {
		evidence += fmt.Sprintf("\n  Syscall events: %d", s.Syscall.TotalCount)
	}
	if s.Sched != nil {
		evidence += fmt.Sprintf("\n  Scheduling events: %d", s.Sched.TotalCount)
	}

	return Finding{
		Severity: SeverityInfo,
		Rule:     "healthy_system",
		Title:    "System Healthy",
		Signal:   "all",
		Cause:    "No issues detected during the analysis window",
		Impact:   "None — all signals are within configured thresholds",
		Evidence: evidence,
		Fix:      []string{"Run kerno doctor --continuous for ongoing monitoring"},
	}
}
