// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"strings"
)

// RuleInfo holds human-readable documentation for a single diagnostic rule.
type RuleInfo struct {
	Name      string
	Signal    string
	Severity  string
	Trigger   string
	Why       string
	Fix       []string
	PairsWith string
}

// ruleCatalog is the canonical list of all rules kerno doctor can fire.
var ruleCatalog = []RuleInfo{
	{
		Name:      "disk_io_bottleneck",
		Signal:    "diskio",
		Severity:  "CRITICAL / WARNING",
		Trigger:   "sync P99 > threshold (default 50ms critical, 20ms warning)",
		Why:       "Storage device is saturated — fsync operations block writers and cascade into application latency.",
		Fix:       []string{"Check disk IOPS: iostat -x 1 5", "Check write queue depth", "Consider faster storage or async fsync"},
		PairsWith: "chaos disk",
	},
	{
		Name:     "oom_kill_occurred",
		Signal:   "oom",
		Severity: "CRITICAL",
		Trigger:  "OOM kill event observed in the BPF ring buffer",
		Why:      "The Linux OOM killer terminated a process because the system ran out of free memory.",
		Fix:      []string{"Increase memory limit or VM size", "Identify the leaking process: kerno watch oom", "Check for memory leaks: valgrind or go tool pprof"},
	},
	{
		Name:      "tcp_retransmit_storm",
		Signal:    "tcp",
		Severity:  "CRITICAL",
		Trigger:   "retransmit rate > threshold (default 5%)",
		Why:       "Network path degradation is causing excessive TCP retransmissions, adding latency to every connection.",
		Fix:       []string{"Check network errors: ethtool -S eth0 | grep -i error", "Check for packet loss: ping -c 100 <gateway>", "Consider pod/service placement to avoid cross-AZ traffic"},
		PairsWith: "chaos network",
	},
	{
		Name:     "tcp_rtt_degradation",
		Signal:   "tcp",
		Severity: "WARNING",
		Trigger:  "TCP RTT P99 > 10ms",
		Why:      "Network latency is higher than expected, adding overhead to every round-trip.",
		Fix:      []string{"Check network path: traceroute <destination>", "Check for congestion: ss -ti", "Consider co-locating services to reduce hops"},
	},
	{
		Name:     "scheduler_contention",
		Signal:   "sched",
		Severity: "CRITICAL / WARNING",
		Trigger:  "run-queue delay P99 > threshold (default 10ms critical, 5ms warning)",
		Why:      "Processes are waiting in the CPU run queue longer than expected, compounding with I/O latency.",
		Fix:      []string{"Check CPU usage: top -H", "Increase CPU count or reduce worker threads", "Check for noisy neighbors on shared nodes"},
	},
	{
		Name:     "fd_leak",
		Signal:   "fd",
		Severity: "WARNING",
		Trigger:  "FD growth rate > threshold (default 10 FDs/sec)",
		Why:      "File descriptors are being opened faster than closed; the process will eventually hit ulimit and crash.",
		Fix:      []string{"Check open FDs: ls /proc/<pid>/fd | wc -l", "Find leak: lsof -p <pid> | head -20", "Ensure response bodies and connections are closed"},
	},
	{
		Name:     "syscall_latency_high",
		Signal:   "syscall",
		Severity: "CRITICAL / WARNING",
		Trigger:  "syscall P99 latency > threshold (default 50ms critical, 10ms warning)",
		Why:      "Kernel system calls are taking longer than expected, usually because the underlying resource (disk, network) is saturated.",
		Fix:      []string{"Profile callers: strace -e trace=<syscall> -p <pid>", "Check if underlying resource (disk, network) is saturated"},
	},
	{
		Name:      "oom_imminent",
		Signal:    "memory",
		Severity:  "CRITICAL / WARNING",
		Trigger:   "memory.UsedPct > 90 AND growth_rate > 0",
		Why:       "Predicts an OOM kill before it happens; lets you scale or shed load while you still have a process to talk to.",
		Fix:       []string{"Increase memory.limits or VM size", "Identify the leaking process: kerno watch oom", "Check top memory consumers: ps aux --sort=-%mem | head"},
		PairsWith: "chaos memory",
	},
	{
		Name:     "syscall_error_rate",
		Signal:   "syscall",
		Severity: "CRITICAL / WARNING",
		Trigger:  "syscall error rate >= 1% (critical at >= 10%)",
		Why:      "A high rate of failing system calls indicates a missing resource, permission problem, or misconfigured application.",
		Fix:      []string{"Trace errors: strace -e trace=<syscall> -Z -p <pid>", "Check if the underlying resource is unavailable"},
	},
	{
		Name:     "memory_limit_pressure",
		Signal:   "cgroup_memory",
		Severity: "CRITICAL / WARNING",
		Trigger:  "container memory > 85% of cgroup limit (critical at > 95% with positive growth)",
		Why:      "Container is approaching its cgroup memory.max limit; the OOM killer will terminate it if usage reaches the limit.",
		Fix:      []string{"Increase the memory limit for the pod", "Profile heap usage: kubectl exec ... -- go tool pprof", "Set memory.high to enable soft throttling before OOM"},
	},
	{
		Name:     "memory_high_throttling",
		Signal:   "cgroup_memory",
		Severity: "WARNING",
		Trigger:  "memory.high reclaim event rate > 1 event/sec",
		Why:      "The kernel is reclaiming memory under the soft limit — an early warning before OOM kill.",
		Fix:      []string{"Increase the memory limit or memory.high setting for the pod", "Review memory allocation patterns", "Check for memory leaks: heap profile or smem"},
	},
	{
		Name:     "healthy_system",
		Signal:   "all",
		Severity: "INFO",
		Trigger:  "no other rule fires",
		Why:      "All kernel signals are within configured thresholds.",
		Fix:      []string{"Run kerno doctor --continuous for ongoing monitoring"},
	},
}

// RuleNames returns a sorted list of all rule names.
func RuleNames() []string {
	names := make([]string, len(ruleCatalog))
	for i, r := range ruleCatalog {
		names[i] = r.Name
	}
	return names
}

// LookupRule returns the RuleInfo for the given name, or an error if not found.
// On miss it suggests the closest matching rule name.
func LookupRule(name string) (RuleInfo, error) {
	for _, r := range ruleCatalog {
		if r.Name == name {
			return r, nil
		}
	}

	// Find closest match (simple prefix / substring suggestion).
	var suggestions []string
	for _, r := range ruleCatalog {
		if strings.Contains(r.Name, name) || strings.Contains(name, strings.Split(r.Name, "_")[0]) {
			suggestions = append(suggestions, r.Name)
		}
	}

	msg := fmt.Sprintf("unknown rule %q", name)
	if len(suggestions) > 0 {
		msg += fmt.Sprintf("\nDid you mean: %s", strings.Join(suggestions, ", "))
	} else {
		msg += fmt.Sprintf("\nRun `kerno explain --rule` to list all available rules")
	}
	return RuleInfo{}, fmt.Errorf("%s", msg)
}

// PrintRuleDoc prints a structured documentation block for a single rule.
func PrintRuleDoc(r RuleInfo) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-10s %s\n", "RULE", r.Name)
	fmt.Fprintf(&sb, "%-10s %s\n", "SIGNAL", r.Signal)
	fmt.Fprintf(&sb, "%-10s %s\n", "SEVERITY", r.Severity)
	fmt.Fprintf(&sb, "%-10s %s\n", "TRIGGER", r.Trigger)
	fmt.Fprintf(&sb, "%-10s %s\n", "WHY", r.Why)
	fmt.Fprintf(&sb, "%-10s\n", "FIX")
	for _, f := range r.Fix {
		fmt.Fprintf(&sb, "           - %s\n", f)
	}
	if r.PairsWith != "" {
		fmt.Fprintf(&sb, "%-10s %s\n", "PAIRS WITH", r.PairsWith)
	}
	return sb.String()
}



