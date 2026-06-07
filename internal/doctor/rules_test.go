// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
)

func defaultThresholds() config.DoctorThresholds {
	return config.Default().Doctor.Thresholds
}

func TestEvaluate_HealthySystem(t *testing.T) {
	signals := &collector.Signals{
		Timestamp: time.Now(),
		Duration:  30 * time.Second,
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "read", Latency: collector.Percentiles{P99: 2 * time.Millisecond}},
			},
			TotalCount: 1000,
		},
		TCP: &collector.TCPSnapshot{
			RetransmitRate: 0.1,
			RTT:            collector.Percentiles{P99: 1 * time.Millisecond},
		},
		Sched: &collector.SchedSnapshot{
			RunqDelay: collector.Percentiles{P99: 500 * time.Microsecond},
		},
		FD: &collector.FDSnapshot{
			GrowthRate: 0.5,
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (healthy), got %d", len(findings))
	}
	if findings[0].Rule != "healthy_system" {
		t.Errorf("expected healthy_system rule, got %q", findings[0].Rule)
	}
	if findings[0].Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", findings[0].Severity)
	}
}

func TestEvaluate_DiskIOBottleneck_Critical(t *testing.T) {
	signals := &collector.Signals{
		DiskIO: &collector.DiskIOSnapshot{
			SyncLatency: collector.Percentiles{P99: 300 * time.Millisecond},
			TotalSyncs:  500,
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	if len(findings) == 0 {
		t.Fatal("expected findings for disk I/O bottleneck")
	}

	found := false
	for _, f := range findings {
		if f.Rule == "disk_io_bottleneck" && f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL disk_io_bottleneck finding")
	}
}

func TestEvaluate_DiskIOBottleneck_Warning(t *testing.T) {
	signals := &collector.Signals{
		DiskIO: &collector.DiskIOSnapshot{
			SyncLatency: collector.Percentiles{P99: 80 * time.Millisecond},
			TotalSyncs:  200,
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "disk_io_bottleneck" && f.Severity == SeverityWarning {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARNING disk_io_bottleneck finding")
	}
}

func TestEvaluate_OOMKill(t *testing.T) {
	signals := &collector.Signals{
		OOM: &collector.OOMSnapshot{
			Events: []collector.OOMEventEntry{
				{PID: 1234, Comm: "postgres", OOMScore: 800, RSSPages: 100000, TotalPages: 110000},
			},
			Count: 1,
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "oom_kill_occurred" && f.Severity == SeverityCritical {
			found = true
			if f.Process != "postgres" {
				t.Errorf("expected process=postgres, got %q", f.Process)
			}
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL oom_kill_occurred finding")
	}
}

func TestEvaluate_TCPRetransmitStorm(t *testing.T) {
	signals := &collector.Signals{
		TCP: &collector.TCPSnapshot{
			RetransmitRate:    5.0,
			TotalRetransmits:  200,
			ActiveConnections: 50,
			TopRetransmitters: []collector.TCPConnectionEntry{
				{SrcAddr: "10.0.1.5", SrcPort: 45000, DstAddr: "10.0.1.10", DstPort: 5432, Retransmits: 80},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "tcp_retransmit_storm" && f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL tcp_retransmit_storm finding")
	}
}

func TestEvaluate_SchedulerContention_Warning(t *testing.T) {
	signals := &collector.Signals{
		Sched: &collector.SchedSnapshot{
			RunqDelay: collector.Percentiles{P99: 8 * time.Millisecond, P50: 1 * time.Millisecond},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "scheduler_contention" && f.Severity == SeverityWarning {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARNING scheduler_contention finding")
	}
}

func TestEvaluate_SchedulerContention_Critical(t *testing.T) {
	signals := &collector.Signals{
		Sched: &collector.SchedSnapshot{
			RunqDelay: collector.Percentiles{P99: 25 * time.Millisecond, P50: 5 * time.Millisecond},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "scheduler_contention" && f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL scheduler_contention finding")
	}
}

func TestEvaluate_FDLeak(t *testing.T) {
	signals := &collector.Signals{
		FD: &collector.FDSnapshot{
			GrowthRate:  20.0,
			TotalOpens:  5000,
			TotalCloses: 4400,
			NetDelta:    600,
			Entries: []collector.FDEntry{
				{PID: 3891, Comm: "app-server", NetDelta: 600, GrowthRate: 20.0},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "fd_leak" {
			found = true
			if f.ETA == nil {
				t.Error("expected ETA for FD leak finding")
			}
			if f.Process != "app-server" {
				t.Errorf("expected process=app-server, got %q", f.Process)
			}
			break
		}
	}
	if !found {
		t.Error("expected fd_leak finding")
	}
}

func TestEvaluate_SyscallLatencyHigh(t *testing.T) {
	signals := &collector.Signals{
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "write", Comm: "postgres", Latency: collector.Percentiles{P99: 312 * time.Millisecond, P50: 50 * time.Millisecond}, Count: 10000},
				{Name: "read", Comm: "app", Latency: collector.Percentiles{P99: 2 * time.Millisecond, P50: 500 * time.Microsecond}, Count: 50000},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "syscall_latency_high" && f.Process == "postgres" {
			found = true
			if f.Severity != SeverityWarning {
				t.Errorf("expected WARNING for 312ms (< 500ms critical), got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected syscall_latency_high finding for postgres")
	}

	// Verify read() at 2ms does NOT trigger a finding.
	for _, f := range findings {
		if f.Rule == "syscall_latency_high" && f.Process == "app" {
			t.Error("read() at 2ms should NOT trigger syscall_latency_high")
		}
	}
}

func TestEvaluate_SyscallLatencyCritical(t *testing.T) {
	signals := &collector.Signals{
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "fsync", Comm: "pg", Latency: collector.Percentiles{P99: 600 * time.Millisecond}, Count: 500},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "syscall_latency_high" && f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL syscall_latency_high for 600ms p99")
	}
}

func TestRankFindings(t *testing.T) {
	eta5m := 5 * time.Minute
	eta30m := 30 * time.Minute

	findings := []Finding{
		{Severity: SeverityWarning, Rule: "warn1"},
		{Severity: SeverityCritical, Rule: "crit1", ETA: &eta30m},
		{Severity: SeverityCritical, Rule: "crit2", ETA: &eta5m},
		{Severity: SeverityInfo, Rule: "info1"},
		{Severity: SeverityCritical, Rule: "crit3"},
	}

	RankFindings(findings)

	// Expected order: crit2 (ETA 5m), crit1 (ETA 30m), crit3 (no ETA), warn1, info1
	if findings[0].Rule != "crit2" {
		t.Errorf("position 0: expected crit2 (shortest ETA), got %s", findings[0].Rule)
	}
	if findings[1].Rule != "crit1" {
		t.Errorf("position 1: expected crit1, got %s", findings[1].Rule)
	}
	if findings[2].Rule != "crit3" {
		t.Errorf("position 2: expected crit3, got %s", findings[2].Rule)
	}
	if findings[3].Rule != "warn1" {
		t.Errorf("position 3: expected warn1, got %s", findings[3].Rule)
	}
	if findings[4].Rule != "info1" {
		t.Errorf("position 4: expected info1, got %s", findings[4].Rule)
	}
}

func TestEvaluate_NilSignals(t *testing.T) {
	// All nil — should produce healthy system finding.
	signals := &collector.Signals{}
	findings := Evaluate(signals, defaultThresholds())
	if len(findings) != 1 || findings[0].Rule != "healthy_system" {
		t.Errorf("expected single healthy_system finding for empty signals, got %d findings", len(findings))
	}
}

func TestEvaluate_OOMImminent_Warning(t *testing.T) {
	signals := &collector.Signals{
		Memory: &collector.MemorySnapshot{
			TotalBytes:            16_000_000_000,
			UsedBytes:             14_800_000_000,
			UsedPct:               92.5,
			GrowthRateBytesPerSec: 0,
			AvailableBytes:        1_200_000_000,
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "oom_imminent" && f.Severity == SeverityWarning {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARNING oom_imminent finding for 92.5% memory usage")
	}
}

func TestEvaluate_OOMImminent_Critical(t *testing.T) {
	signals := &collector.Signals{
		Memory: &collector.MemorySnapshot{
			TotalBytes:            16_000_000_000,
			UsedBytes:             15_500_000_000,
			UsedPct:               96.9,
			GrowthRateBytesPerSec: 50_000_000, // 50MB/sec growth
			AvailableBytes:        500_000_000,
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "oom_imminent" && f.Severity == SeverityCritical {
			found = true
			if f.ETA == nil {
				t.Error("expected ETA for OOM imminent with positive growth rate")
			}
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL oom_imminent finding for 96.9% + growing")
	}
}

func TestEvaluate_OOMImminent_BelowThreshold(t *testing.T) {
	signals := &collector.Signals{
		Memory: &collector.MemorySnapshot{
			TotalBytes: 16_000_000_000,
			UsedBytes:  12_000_000_000,
			UsedPct:    75.0,
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "oom_imminent" {
			t.Error("should not trigger oom_imminent at 75% memory")
		}
	}
}

func TestEvaluate_SyscallErrorRate_Warning(t *testing.T) {
	signals := &collector.Signals{
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "open", Comm: "app", Count: 1000, ErrorCount: 30, Latency: collector.Percentiles{P99: 1 * time.Millisecond}},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "syscall_error_rate" && f.Severity == SeverityWarning {
			found = true
			if f.Process != "app" {
				t.Errorf("expected process=app, got %q", f.Process)
			}
			break
		}
	}
	if !found {
		t.Error("expected WARNING syscall_error_rate for 3% error rate")
	}
}

func TestEvaluate_SyscallErrorRate_Critical(t *testing.T) {
	signals := &collector.Signals{
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "connect", Comm: "client", Count: 100, ErrorCount: 15, Latency: collector.Percentiles{P99: 5 * time.Millisecond}},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "syscall_error_rate" && f.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL syscall_error_rate for 15% error rate")
	}
}

func TestEvaluate_SyscallErrorRate_BelowThreshold(t *testing.T) {
	signals := &collector.Signals{
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "read", Comm: "app", Count: 10000, ErrorCount: 5, Latency: collector.Percentiles{P99: 1 * time.Millisecond}},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "syscall_error_rate" {
			t.Error("should not trigger syscall_error_rate at 0.05% error rate")
		}
	}
}

func TestEvaluate_MemoryLimitPressure_Warning(t *testing.T) {
	limitBytes := uint64(4 << 30)
	currentBytes := uint64(float64(limitBytes) * 0.88)
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					CgroupPath:   "/sys/fs/cgroup/kubepods/burstable/pod-redis/ctr0",
					Pod:          "pod-redis",
					LimitBytes:   limitBytes,
					CurrentBytes: currentBytes,
					UsedPct:      88.0,
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "memory_limit_pressure" && f.Severity == SeverityWarning {
			found = true
			if f.Process != "pod-redis" {
				t.Errorf("expected Process=pod-redis, got %q", f.Process)
			}
			break
		}
	}
	if !found {
		t.Error("expected WARNING memory_limit_pressure at 88%")
	}
}

func TestEvaluate_MemoryLimitPressure_CriticalWithETA(t *testing.T) {
	limit := uint64(4 << 30) // 4 GiB
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					CgroupPath:            "/sys/fs/cgroup/kubepods/burstable/pod-kafka/ctr0",
					Pod:                   "pod-kafka",
					LimitBytes:            limit,
					CurrentBytes:          uint64(float64(limit) * 0.96),
					UsedPct:               96.0,
					GrowthRateBytesPerSec: 7.2 * 1024 * 1024, // 7.2 MB/s
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "memory_limit_pressure" && f.Severity == SeverityCritical {
			found = true
			if f.ETA == nil {
				t.Error("expected ETA for critical memory_limit_pressure with growth > 1 MB/s")
			}
			if f.Process != "pod-kafka" {
				t.Errorf("expected Process=pod-kafka, got %q", f.Process)
			}
			break
		}
	}
	if !found {
		t.Error("expected CRITICAL memory_limit_pressure at 96% + growing")
	}
}

func TestEvaluate_MemoryLimitPressure_CriticalNoETA(t *testing.T) {
	limit := uint64(4 << 30)
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					Pod:                   "pod-slow",
					LimitBytes:            limit,
					CurrentBytes:          uint64(float64(limit) * 0.97),
					UsedPct:               97.0,
					GrowthRateBytesPerSec: 500 * 1024, // 500 KB/s — below 1 MB/s threshold
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "memory_limit_pressure" && f.Severity == SeverityCritical {
			if f.ETA != nil {
				t.Error("should not compute ETA when growth rate < 1 MB/s")
			}
			return
		}
	}
	t.Error("expected CRITICAL memory_limit_pressure finding")
}

func TestEvaluate_MemoryLimitPressure_ExactlyAt95(t *testing.T) {
	limit := uint64(4 << 30)
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					Pod:                   "pod-boundary",
					LimitBytes:            limit,
					CurrentBytes:          uint64(float64(limit) * 0.95),
					UsedPct:               95.0,
					GrowthRateBytesPerSec: 2 * 1024 * 1024, // 2 MB/s — growing
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "memory_limit_pressure" {
			if f.Severity != SeverityCritical {
				t.Errorf("expected CRITICAL at exactly 95%%, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("expected memory_limit_pressure finding at exactly 95%")
}

func TestEvaluate_MemoryLimitPressure_BelowThreshold(t *testing.T) {
	limit := uint64(4 << 30)
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					Pod:          "pod-ok",
					LimitBytes:   limit,
					CurrentBytes: uint64(float64(limit) * 0.70),
					UsedPct:      70.0,
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "memory_limit_pressure" {
			t.Error("should not fire memory_limit_pressure at 70%")
		}
	}
}

func TestEvaluate_MemoryLimitPressure_NilCgroupMemory(t *testing.T) {
	signals := &collector.Signals{}
	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "memory_limit_pressure" {
			t.Error("should not fire memory_limit_pressure when CgroupMemory is nil")
		}
	}
}

func TestEvaluate_MemoryHighThrottling_Warning(t *testing.T) {
	limit := uint64(2 << 30)
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					Pod:           "pod-throttled",
					LimitBytes:    limit,
					CurrentBytes:  uint64(float64(limit) * 0.82),
					UsedPct:       82.0,
					HighBytes:     uint64(float64(limit) * 0.80),
					HighEventRate: 3.5, // 3.5 events/sec > 1/sec threshold
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	found := false
	for _, f := range findings {
		if f.Rule == "memory_high_throttling" && f.Severity == SeverityWarning {
			found = true
			if f.Process != "pod-throttled" {
				t.Errorf("expected Process=pod-throttled, got %q", f.Process)
			}
			break
		}
	}
	if !found {
		t.Error("expected WARNING memory_high_throttling at 3.5 events/sec")
	}
}

func TestEvaluate_MemoryHighThrottling_BelowThreshold(t *testing.T) {
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					Pod:           "pod-ok",
					LimitBytes:    2 << 30,
					CurrentBytes:  1 << 29,
					UsedPct:       25.0,
					HighEventRate: 0.5, // < 1/sec
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "memory_high_throttling" {
			t.Error("should not fire memory_high_throttling at 0.5 events/sec")
		}
	}
}

func TestEvaluate_MemoryLimitPressure_WithNamespace(t *testing.T) {
	limit := uint64(4 << 30)
	signals := &collector.Signals{
		CgroupMemory: &collector.CgroupMemorySnapshot{
			Containers: []collector.CgroupMemoryEntry{
				{
					Pod:                   "kafka-broker-2",
					Namespace:             "production",
					LimitBytes:            limit,
					CurrentBytes:          uint64(float64(limit) * 0.96),
					UsedPct:               96.0,
					GrowthRateBytesPerSec: 7.2 * 1024 * 1024,
				},
			},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	for _, f := range findings {
		if f.Rule == "memory_limit_pressure" {
			if !containsString(f.Title, "production/kafka-broker-2") {
				t.Errorf("expected namespace/pod in title, got: %q", f.Title)
			}
			return
		}
	}
	t.Error("expected memory_limit_pressure finding")
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

func TestEvaluate_MultipleFindings(t *testing.T) {
	signals := &collector.Signals{
		DiskIO: &collector.DiskIOSnapshot{
			SyncLatency: collector.Percentiles{P99: 300 * time.Millisecond},
			TotalSyncs:  500,
		},
		TCP: &collector.TCPSnapshot{
			RetransmitRate:    5.0,
			TotalRetransmits:  200,
			ActiveConnections: 50,
		},
		Sched: &collector.SchedSnapshot{
			RunqDelay: collector.Percentiles{P99: 8 * time.Millisecond},
		},
	}

	findings := Evaluate(signals, defaultThresholds())
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(findings))
	}

	// Verify ordering: CRITICAL findings should come first.
	for i := 1; i < len(findings); i++ {
		if findings[i].Severity > findings[i-1].Severity {
			t.Errorf("findings not sorted: %s at position %d has higher severity than %s at position %d",
				findings[i].Rule, i, findings[i-1].Rule, i-1)
		}
	}
}

func TestPredict_DiskIOSaturation(t *testing.T) {
	now := time.Now()
	snapshots := []*collector.Signals{
		{
			Timestamp: now,
			DiskIO: &collector.DiskIOSnapshot{
				SyncLatency: collector.Percentiles{P99: 10 * time.Millisecond},
			},
		},
		{
			Timestamp: now.Add(10 * time.Second),
			DiskIO: &collector.DiskIOSnapshot{
				SyncLatency: collector.Percentiles{P99: 20 * time.Millisecond},
			},
		},
		{
			Timestamp: now.Add(20 * time.Second),
			DiskIO: &collector.DiskIOSnapshot{
				SyncLatency: collector.Percentiles{P99: 30 * time.Millisecond},
			},
		},
	}

	report := Predict(snapshots)
	if len(report.Predictions) == 0 {
		t.Fatal("expected at least 1 prediction")
	}

	found := false
	for _, p := range report.Predictions {
		if p.Signal == "diskio" {
			found = true
			if p.TimeToImpact <= 0 {
				t.Errorf("expected positive time to impact, got %v", p.TimeToImpact)
			}
			break
		}
	}
	if !found {
		t.Error("expected diskio prediction")
	}
}

func TestPredict_DiskIOSaturation_NilSnapshots(t *testing.T) {
	now := time.Now()
	snapshots := []*collector.Signals{
		{
			Timestamp: now,
			DiskIO: &collector.DiskIOSnapshot{
				SyncLatency: collector.Percentiles{P99: 10 * time.Millisecond},
			},
		},
		{
			Timestamp: now.Add(10 * time.Second),
			DiskIO:    nil,
		},
		{
			Timestamp: now.Add(20 * time.Second),
			DiskIO: &collector.DiskIOSnapshot{
				SyncLatency: collector.Percentiles{P99: 20 * time.Millisecond},
			},
		},
		{
			Timestamp: now.Add(30 * time.Second),
			DiskIO: &collector.DiskIOSnapshot{
				SyncLatency: collector.Percentiles{P99: 30 * time.Millisecond},
			},
		},
	}

	report := Predict(snapshots)
	if len(report.Predictions) == 0 {
		t.Fatal("expected at least 1 prediction")
	}

	found := false
	for _, p := range report.Predictions {
		if p.Signal == "diskio" {
			found = true
			if p.TimeToImpact <= 0 {
				t.Errorf("expected positive time to impact, got %v", p.TimeToImpact)
			}
			break
		}
	}
	if !found {
		t.Error("expected diskio prediction")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{512, "512B"},
		{4096, "4.0KB"},
		{1 << 20, "1.0MB"},
		{1 << 30, "1.0GB"},
		{1 << 40, "1.0TB"},
		{1 << 50, "1.0PB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.in); got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
