// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"strings"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
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
	findings = append(findings, evalMemoryLimitPressure(signals)...)
	findings = append(findings, evalMemoryHighThrottling(signals)...)

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

	findings := make([]Finding, 0, len(s.OOM.Events))
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

	// Estimate time to fd limit.
	if s.FD.GrowthRate > 0 {
		// Use the top leaker's stats when available, fall back to snapshot-level values.
		var currentFDs, netDelta int64
		var fdLimit int
		if len(s.FD.Entries) > 0 {
			top := s.FD.Entries[0]
			currentFDs = int64(top.CurrentFDs)
			netDelta = top.NetDelta
			fdLimit = top.FDLimit
		} else {
			netDelta = s.FD.NetDelta
		}

		remaining, limit, exact := fdHeadroom(currentFDs, netDelta, fdLimit)
		etaSecs := remaining / s.FD.GrowthRate
		if eta, ok := etaDuration(etaSecs); ok {
			f.ETA = &eta
			qualifier := ""
			if !exact {
				qualifier = " (estimated from window delta — actual may be lower)"
			}
			f.Impact = fmt.Sprintf(
				"Process will hit fd limit (%d) in %s at current growth rate%s",
				int(limit), f.ETAString(), qualifier,
			)
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

// evalSyscallLatencyHigh emits at most one finding per run, even when many
// (syscall, comm) pairs cross the threshold. The worst pair drives severity
// and the headline; up to 5 next-worst pairs are listed in evidence.
// Emitting a finding per pair would swamp the report and obscure other rules.
func evalSyscallLatencyHigh(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.Syscall == nil {
		return nil
	}

	warningNs := time.Duration(t.SyscallP99WarningNs)
	criticalNs := time.Duration(t.SyscallP99CriticalNs)

	hot := make([]collector.SyscallEntry, 0, len(s.Syscall.Entries))
	sev := SeverityWarning
	for _, entry := range s.Syscall.Entries {
		// Voluntary-blocking syscalls (futex, epoll_wait, poll, ...)
		// have latency dominated by userspace wait time, not by the
		// kernel — flagging them produces false positives on idle hosts.
		if bpf.IsBlockingSyscall(entry.SyscallNr) {
			continue
		}
		if entry.Latency.P99 < warningNs {
			continue
		}
		hot = append(hot, entry)
		if entry.Latency.P99 >= criticalNs {
			sev = SeverityCritical
		}
	}
	if len(hot) == 0 {
		return nil
	}

	// SyscallSnapshot.Entries is already sorted by P99 desc by the collector.
	top := hot[0]
	topName := top.Name
	if topName == "" {
		topName = fmt.Sprintf("syscall_%d", top.SyscallNr)
	}

	thresh := warningNs
	if sev == SeverityCritical {
		thresh = criticalNs
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "%d (syscall, comm) pairs exceed P99=%s. Top:", len(hot), thresh)
	for i, e := range hot {
		if i >= 6 {
			break
		}
		nm := e.Name
		if nm == "" {
			nm = fmt.Sprintf("syscall_%d", e.SyscallNr)
		}
		fmt.Fprintf(&ev, " %s(%s)@%s", nm, e.Comm, e.Latency.P99)
	}

	title := fmt.Sprintf("High Syscall Latency (%d affected)", len(hot))
	if len(hot) == 1 {
		title = fmt.Sprintf("High %s() Syscall Latency", topName)
	}

	return []Finding{{
		Severity:  sev,
		Rule:      "syscall_latency_high",
		Title:     title,
		Signal:    "syscall",
		Cause:     fmt.Sprintf("%s() P99 latency exceeds threshold (top of %d affected)", topName, len(hot)),
		Impact:    fmt.Sprintf("Worst case: %s in %s()", top.Latency.P99, topName),
		Evidence:  ev.String(),
		Fix:       []string{fmt.Sprintf("Profile callers: strace -e trace=%s -p <pid>", topName), "Check if underlying resource (disk, network) is saturated"},
		Metric:    "syscall_p99_max",
		Value:     float64(top.Latency.P99.Nanoseconds()),
		Threshold: float64(thresh.Nanoseconds()),
		Process:   top.Comm,
	}}
}

// ── Rule 9: OOM Imminent ─────────────────────────────────────────────────────

func evalOOMImminent(s *collector.Signals, t config.DoctorThresholds) []Finding {
	if s.Memory == nil {
		return nil
	}

	threshold := t.OOMMemoryPct
	// Negative threshold disables the rule. Zero is treated literally
	// (fires on any non-zero usage) — useful for tests; default config
	// supplies 90.0 for production.
	if threshold < 0 {
		return nil
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
		if eta, ok := etaDuration(etaSecs); ok {
			f.ETA = &eta
			f.Impact = fmt.Sprintf("At current growth rate, memory will be exhausted in %s", f.ETAString())
		}
	}

	return []Finding{f}
}

// ── Rule 10: Syscall Error Rate ──────────────────────────────────────────────

// evalSyscallErrorRate emits at most one finding per run. See the same
// invariant note on evalSyscallLatencyHigh.
func evalSyscallErrorRate(s *collector.Signals) []Finding {
	if s.Syscall == nil {
		return nil
	}

	type hot struct {
		entry collector.SyscallEntry
		rate  float64
	}
	entries := make([]hot, 0, len(s.Syscall.Entries))
	sev := SeverityWarning
	for _, entry := range s.Syscall.Entries {
		// Blocking syscalls return EAGAIN/ETIMEDOUT/ECHILD as part of
		// normal operation (e.g., wait4 with no children, epoll_wait
		// timeout). Exclude them or every idle host looks broken.
		if bpf.IsBlockingSyscall(entry.SyscallNr) {
			continue
		}
		if entry.Count == 0 || entry.ErrorCount == 0 {
			continue
		}
		rate := float64(entry.ErrorCount) / float64(entry.Count) * 100.0
		if rate < 1.0 {
			continue
		}
		if rate >= 10.0 {
			sev = SeverityCritical
		}
		entries = append(entries, hot{entry, rate})
	}
	if len(entries) == 0 {
		return nil
	}

	// Pick the worst (highest error rate) entry as headline.
	top := entries[0]
	for _, e := range entries[1:] {
		if e.rate > top.rate {
			top = e
		}
	}
	name := top.entry.Name
	if name == "" {
		name = fmt.Sprintf("syscall_%d", top.entry.SyscallNr)
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "%d syscalls have error rate ≥ 1%%. Worst: %s(%s)=%.1f%% (%d/%d).",
		len(entries), name, top.entry.Comm, top.rate, top.entry.ErrorCount, top.entry.Count)

	title := fmt.Sprintf("High Syscall Error Rate (%d affected)", len(entries))
	if len(entries) == 1 {
		title = fmt.Sprintf("High %s() Error Rate", name)
	}

	return []Finding{{
		Severity:  sev,
		Rule:      "syscall_error_rate",
		Title:     title,
		Signal:    "syscall",
		Cause:     fmt.Sprintf("%s() is failing %.1f%% of the time", name, top.rate),
		Impact:    fmt.Sprintf("%d out of %d %s() calls are returning errors", top.entry.ErrorCount, top.entry.Count, name),
		Evidence:  ev.String(),
		Fix:       []string{fmt.Sprintf("Trace errors: strace -e trace=%s -Z -p <pid>", name), "Check if the underlying resource is unavailable"},
		Metric:    "syscall_error_pct_max",
		Value:     top.rate,
		Threshold: 1.0,
		Process:   top.entry.Comm,
	}}
}

// ── Rule 12: Memory Limit Pressure ──────────────────────────────────────────

// evalMemoryLimitPressure fires for each container that is close to its
// cgroup v2 memory.max limit. WARNING at >85 %; CRITICAL at >95 % with
// positive growth rate. Includes an ETA when growth rate exceeds 1 MB/s.
func evalMemoryLimitPressure(s *collector.Signals) []Finding {
	if s.CgroupMemory == nil {
		return nil
	}

	findings := make([]Finding, 0, len(s.CgroupMemory.Containers))
	for _, c := range s.CgroupMemory.Containers {
		if c.LimitBytes == 0 || c.UsedPct < 85.0 {
			continue
		}

		sev := SeverityWarning
		threshold := 85.0
		if c.UsedPct >= 95.0 && c.GrowthRateBytesPerSec > 0 {
			sev = SeverityCritical
			threshold = 95.0
		}

		label := c.Pod
		if c.Namespace != "" {
			label = c.Namespace + "/" + c.Pod
		}

		growthMBs := c.GrowthRateBytesPerSec / (1024 * 1024)

		title := fmt.Sprintf("%s is %.0f%% of its memory limit (%s / %s)",
			label, c.UsedPct, formatBytes(c.CurrentBytes), formatBytes(c.LimitBytes))

		impact := fmt.Sprintf("OOM kill will terminate container %s if usage reaches the limit", label)

		f := Finding{
			Severity: sev,
			Rule:     "memory_limit_pressure",
			Title:    title,
			Signal:   "cgroup_memory",
			Cause:    fmt.Sprintf("Container memory usage is at %.1f%% of its cgroup limit", c.UsedPct),
			Impact:   impact,
			Evidence: fmt.Sprintf(
				"current=%s limit=%s used=%.1f%% growth=%.1f MB/s events(high=%d oom=%d oom_kill=%d)",
				formatBytes(c.CurrentBytes), formatBytes(c.LimitBytes), c.UsedPct,
				growthMBs, c.EventsHigh, c.EventsOOM, c.EventsOOMKill),
			Fix: []string{
				fmt.Sprintf("Increase the memory limit for pod %s", c.Pod),
				"Profile heap usage: kubectl exec ... -- pprof / jmap / go tool pprof",
				"Consider setting memory.high to enable soft throttling before OOM",
			},
			Metric:    "cgroup_memory_used_pct",
			Value:     c.UsedPct,
			Threshold: threshold,
			Process:   c.Pod,
		}

		// ETA is only meaningful when growth rate is significant (>1 MB/s).
		if sev == SeverityCritical {
			const minGrowthForETA = 1 << 20 // 1 MB/s
			if c.GrowthRateBytesPerSec >= minGrowthForETA && c.LimitBytes > c.CurrentBytes {
				remaining := c.LimitBytes - c.CurrentBytes
				etaSecs := float64(remaining) / c.GrowthRateBytesPerSec
				if eta, ok := etaDuration(etaSecs); ok {
					f.ETA = &eta
					f.Impact = fmt.Sprintf(
						"%s is %.0f%% of its memory limit (%s / %s) and growing %.1f MB/s. OOMKill expected in %s.",
						label, c.UsedPct,
						formatBytes(c.CurrentBytes), formatBytes(c.LimitBytes),
						growthMBs, f.ETAString())
				} else {
					f.Impact = fmt.Sprintf(
						"%s is %.0f%% of its memory limit (%s / %s) and trending up, but no reliable ETA available.",
						label, c.UsedPct, formatBytes(c.CurrentBytes), formatBytes(c.LimitBytes))
				}
			} else {
				f.Impact = fmt.Sprintf(
					"%s is %.0f%% of its memory limit (%s / %s) and trending up, but no reliable ETA available (growth rate < 1 MB/s).",
					label, c.UsedPct, formatBytes(c.CurrentBytes), formatBytes(c.LimitBytes))
			}
		}

		findings = append(findings, f)
	}
	return findings
}

// ── Rule 13: Memory High Throttling ─────────────────────────────────────────

// evalMemoryHighThrottling fires when the kernel is reclaiming memory under
// the memory.high soft limit at a sustained rate of more than 1 event/sec.
// This is an early warning before any OOM kill.
func evalMemoryHighThrottling(s *collector.Signals) []Finding {
	if s.CgroupMemory == nil {
		return nil
	}

	findings := make([]Finding, 0, len(s.CgroupMemory.Containers))
	for _, c := range s.CgroupMemory.Containers {
		if c.HighEventRate < 1.0 {
			continue
		}

		label := c.Pod
		if c.Namespace != "" {
			label = c.Namespace + "/" + c.Pod
		}

		findings = append(findings, Finding{
			Severity: SeverityWarning,
			Rule:     "memory_high_throttling",
			Title:    fmt.Sprintf("Memory High Throttling: %s", label),
			Signal:   "cgroup_memory",
			Cause: fmt.Sprintf(
				"Kernel is reclaiming memory under memory.high pressure at %.1f events/sec", c.HighEventRate),
			Impact: "Container throughput is being throttled; risk of OOMKill increases if usage continues to rise",
			Evidence: fmt.Sprintf(
				"high_event_rate=%.1f/sec high_limit=%s current=%s max=%s",
				c.HighEventRate, formatBytes(c.HighBytes), formatBytes(c.CurrentBytes), formatBytes(c.LimitBytes)),
			Fix: []string{
				fmt.Sprintf("Increase the memory limit or memory.high setting for pod %s", c.Pod),
				"Review memory allocation patterns and look for unexpected growth",
				"Check for memory leaks: heap profile or smem",
			},
			Metric:    "cgroup_memory_high_event_rate",
			Value:     c.HighEventRate,
			Threshold: 1.0,
			Process:   c.Pod,
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
		tB = gB * 1024
		pB = tB * 1024
	)
	switch {
	case b >= pB:
		return fmt.Sprintf("%.1fPB", float64(b)/float64(pB))
	case b >= tB:
		return fmt.Sprintf("%.1fTB", float64(b)/float64(tB))
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
