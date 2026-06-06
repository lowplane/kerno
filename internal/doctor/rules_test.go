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

// findingFor returns the first finding matching rule, or nil.
func findingFor(findings []Finding, rule string) *Finding {
	for i := range findings {
		if findings[i].Rule == rule {
			return &findings[i]
		}
	}
	return nil
}

// findingForSeverity returns the first finding matching rule+severity, or nil.
func findingForSeverity(findings []Finding, rule string, sev Severity) *Finding {
	for i := range findings {
		if findings[i].Rule == rule && findings[i].Severity == sev {
			return &findings[i]
		}
	}
	return nil
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

// ─── Healthy system ───────────────────────────────────────────────────────────

func TestEvaluate_HealthySystem(t *testing.T) {
	tests := []struct {
		name    string
		signals *collector.Signals
	}{
		{
			name:    "empty signals",
			signals: &collector.Signals{},
		},
		{
			name: "all metrics well below threshold",
			signals: &collector.Signals{
				Timestamp: time.Now(),
				Duration:  30 * time.Second,
				Syscall: &collector.SyscallSnapshot{
					Entries:    []collector.SyscallEntry{{Name: "read", Latency: collector.Percentiles{P99: 2 * time.Millisecond}}},
					TotalCount: 1000,
				},
				TCP: &collector.TCPSnapshot{
					RetransmitRate: 0.1,
					RTT:            collector.Percentiles{P99: 1 * time.Millisecond},
				},
				Sched: &collector.SchedSnapshot{
					RunqDelay: collector.Percentiles{P99: 500 * time.Microsecond},
				},
				FD: &collector.FDSnapshot{GrowthRate: 0.5},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := Evaluate(tc.signals, defaultThresholds())
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding (healthy), got %d", len(findings))
			}
			if findings[0].Rule != "healthy_system" {
				t.Errorf("expected healthy_system rule, got %q", findings[0].Rule)
			}
			if findings[0].Severity != SeverityInfo {
				t.Errorf("expected INFO severity, got %s", findings[0].Severity)
			}
		})
	}
}

// ─── Disk I/O bottleneck ──────────────────────────────────────────────────────

func TestEvaluate_DiskIOBottleneck(t *testing.T) {
	tests := []struct {
		name         string
		syncLatency  time.Duration
		totalSyncs   uint64
		wantRule     string
		wantSeverity Severity
		wantFinding  bool
	}{
		{
			name:        "below threshold — no finding",
			syncLatency: 10 * time.Millisecond,
			totalSyncs:  10,
			wantFinding: false,
		},
		{
			name:         "exactly at warning threshold",
			syncLatency:  50 * time.Millisecond,
			totalSyncs:   100,
			wantRule:     "disk_io_bottleneck",
			wantSeverity: SeverityWarning,
			wantFinding:  true,
		},
		{
			name:         "warning — 80ms sync latency",
			syncLatency:  80 * time.Millisecond,
			totalSyncs:   200,
			wantRule:     "disk_io_bottleneck",
			wantSeverity: SeverityWarning,
			wantFinding:  true,
		},
		{
			name:         "critical — 300ms sync latency",
			syncLatency:  300 * time.Millisecond,
			totalSyncs:   500,
			wantRule:     "disk_io_bottleneck",
			wantSeverity: SeverityCritical,
			wantFinding:  true,
		},
		{
			name:         "one past critical threshold",
			syncLatency:  201 * time.Millisecond,
			totalSyncs:   300,
			wantRule:     "disk_io_bottleneck",
			wantSeverity: SeverityCritical,
			wantFinding:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signals := &collector.Signals{
				DiskIO: &collector.DiskIOSnapshot{
					SyncLatency: collector.Percentiles{P99: tc.syncLatency},
					TotalSyncs:  tc.totalSyncs,
				},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingForSeverity(findings, tc.wantRule, tc.wantSeverity)
			if tc.wantFinding && f == nil {
				t.Errorf("expected %s %s finding, got none (findings: %v)", tc.wantSeverity, tc.wantRule, findings)
			}
			if !tc.wantFinding {
				if bad := findingFor(findings, "disk_io_bottleneck"); bad != nil {
					t.Errorf("expected no disk_io_bottleneck finding, got %+v", bad)
				}
			}
		})
	}
}

// ─── OOM kill ─────────────────────────────────────────────────────────────────

func TestEvaluate_OOMKill(t *testing.T) {
	tests := []struct {
		name        string
		events      []collector.OOMEventEntry
		count       uint64
		wantFinding bool
		wantProcess string
	}{
		{
			name:        "no OOM events — no finding",
			events:      nil,
			count:       0,
			wantFinding: false,
		},
		{
			name: "single OOM kill",
			events: []collector.OOMEventEntry{
				{PID: 1234, Comm: "postgres", OOMScore: 800, RSSPages: 100000, TotalPages: 110000},
			},
			count:       1,
			wantFinding: true,
			wantProcess: "postgres",
		},
		{
			name: "multiple OOM kills — top victim reported",
			events: []collector.OOMEventEntry{
				{PID: 100, Comm: "redis", OOMScore: 900, RSSPages: 200000, TotalPages: 210000},
				{PID: 200, Comm: "nginx", OOMScore: 500, RSSPages: 50000, TotalPages: 210000},
			},
			count:       2,
			wantFinding: true,
			wantProcess: "redis",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signals := &collector.Signals{
				OOM: &collector.OOMSnapshot{Events: tc.events, Count: tc.count},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingForSeverity(findings, "oom_kill_occurred", SeverityCritical)
			if tc.wantFinding {
				if f == nil {
					t.Fatal("expected CRITICAL oom_kill_occurred finding, got none")
				}
				if tc.wantProcess != "" && f.Process != tc.wantProcess {
					t.Errorf("expected process=%q, got %q", tc.wantProcess, f.Process)
				}
			} else {
				if f != nil {
					t.Errorf("expected no oom_kill_occurred finding, got %+v", f)
				}
			}
		})
	}
}

// ─── TCP retransmit storm ─────────────────────────────────────────────────────

func TestEvaluate_TCPRetransmitStorm(t *testing.T) {
	tests := []struct {
		name             string
		retransmitRate   float64
		totalRetransmits uint64
		activeConns      uint64
		wantFinding      bool
		wantSeverity     Severity
	}{
		{
			name:           "below threshold — no finding",
			retransmitRate: 0.5,
			wantFinding:    false,
		},
		{
			name:             "critical — 5% retransmit rate",
			retransmitRate:   5.0,
			totalRetransmits: 200,
			activeConns:      50,
			wantFinding:      true,
			wantSeverity:     SeverityCritical,
		},
		{
			name:             "one past critical threshold",
			retransmitRate:   3.1,
			totalRetransmits: 100,
			activeConns:      30,
			wantFinding:      true,
			wantSeverity:     SeverityCritical,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signals := &collector.Signals{
				TCP: &collector.TCPSnapshot{
					RetransmitRate:    tc.retransmitRate,
					TotalRetransmits:  tc.totalRetransmits,
					ActiveConnections: tc.activeConns,
					TopRetransmitters: []collector.TCPConnectionEntry{
						{SrcAddr: "10.0.1.5", SrcPort: 45000, DstAddr: "10.0.1.10", DstPort: 5432, Retransmits: 80},
					},
				},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingForSeverity(findings, "tcp_retransmit_storm", tc.wantSeverity)
			if tc.wantFinding && f == nil {
				t.Errorf("expected %s tcp_retransmit_storm finding, got none", tc.wantSeverity)
			}
			if !tc.wantFinding {
				if bad := findingFor(findings, "tcp_retransmit_storm"); bad != nil {
					t.Errorf("expected no tcp_retransmit_storm finding, got %+v", bad)
				}
			}
		})
	}
}

// ─── Scheduler contention ─────────────────────────────────────────────────────

func TestEvaluate_SchedulerContention(t *testing.T) {
	tests := []struct {
		name         string
		p99          time.Duration
		p50          time.Duration
		wantFinding  bool
		wantSeverity Severity
	}{
		{
			name:        "below threshold — no finding",
			p99:         500 * time.Microsecond,
			wantFinding: false,
		},
		{
			name:         "exactly at warning threshold",
			p99:          5 * time.Millisecond,
			p50:          1 * time.Millisecond,
			wantFinding:  true,
			wantSeverity: SeverityWarning,
		},
		{
			name:         "warning — 8ms p99",
			p99:          8 * time.Millisecond,
			p50:          1 * time.Millisecond,
			wantFinding:  true,
			wantSeverity: SeverityWarning,
		},
		{
			name:         "critical — 25ms p99",
			p99:          25 * time.Millisecond,
			p50:          5 * time.Millisecond,
			wantFinding:  true,
			wantSeverity: SeverityCritical,
		},
		{
			name:         "one past critical threshold",
			p99:          21 * time.Millisecond,
			p50:          4 * time.Millisecond,
			wantFinding:  true,
			wantSeverity: SeverityCritical,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signals := &collector.Signals{
				Sched: &collector.SchedSnapshot{
					RunqDelay: collector.Percentiles{P99: tc.p99, P50: tc.p50},
				},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingForSeverity(findings, "scheduler_contention", tc.wantSeverity)
			if tc.wantFinding && f == nil {
				t.Errorf("expected %s scheduler_contention finding, got none", tc.wantSeverity)
			}
			if !tc.wantFinding {
				if bad := findingFor(findings, "scheduler_contention"); bad != nil {
					t.Errorf("expected no scheduler_contention finding, got %+v", bad)
				}
			}
		})
	}
}

// ─── FD leak ──────────────────────────────────────────────────────────────────

func TestEvaluate_FDLeak(t *testing.T) {
	tests := []struct {
		name        string
		growthRate  float64
		totalOpens  uint64
		totalCloses uint64
		netDelta    int64
		process     string
		wantFinding bool
		wantETA     bool
	}{
		{
			name:        "below threshold — no finding",
			growthRate:  0.5,
			wantFinding: false,
		},
		{
			name:        "fd leak detected with ETA",
			growthRate:  20.0,
			totalOpens:  5000,
			totalCloses: 4400,
			netDelta:    600,
			process:     "app-server",
			wantFinding: true,
			wantETA:     true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entries := []collector.FDEntry{}
			if tc.process != "" {
				entries = append(entries, collector.FDEntry{
					PID: 3891, Comm: tc.process, NetDelta: tc.netDelta, GrowthRate: tc.growthRate,
				})
			}
			signals := &collector.Signals{
				FD: &collector.FDSnapshot{
					GrowthRate:  tc.growthRate,
					TotalOpens:  tc.totalOpens,
					TotalCloses: tc.totalCloses,
					NetDelta:    tc.netDelta,
					Entries:     entries,
				},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingFor(findings, "fd_leak")
			if tc.wantFinding {
				if f == nil {
					t.Fatal("expected fd_leak finding, got none")
				}
				if tc.wantETA && f.ETA == nil {
					t.Error("expected ETA for FD leak finding")
				}
				if tc.process != "" && f.Process != tc.process {
					t.Errorf("expected process=%q, got %q", tc.process, f.Process)
				}
			} else {
				if f != nil {
					t.Errorf("expected no fd_leak finding, got %+v", f)
				}
			}
		})
	}
}

// ─── Syscall latency ──────────────────────────────────────────────────────────

func TestEvaluate_SyscallLatency(t *testing.T) {
	tests := []struct {
		name         string
		entries      []collector.SyscallEntry
		wantRule     string
		wantProcess  string
		wantSeverity Severity
		wantFinding  bool
		wantAbsent   string // process that must NOT trigger the rule
	}{
		{
			name: "below threshold — no finding",
			entries: []collector.SyscallEntry{
				{Name: "read", Comm: "app", Latency: collector.Percentiles{P99: 2 * time.Millisecond}, Count: 1000},
			},
			wantFinding: false,
		},
		{
			name: "warning — 312ms p99 (below 500ms critical)",
			entries: []collector.SyscallEntry{
				{Name: "write", Comm: "postgres", Latency: collector.Percentiles{P99: 312 * time.Millisecond, P50: 50 * time.Millisecond}, Count: 10000},
				{Name: "read", Comm: "app", Latency: collector.Percentiles{P99: 2 * time.Millisecond, P50: 500 * time.Microsecond}, Count: 50000},
			},
			wantRule:     "syscall_latency_high",
			wantProcess:  "postgres",
			wantSeverity: SeverityWarning,
			wantFinding:  true,
			wantAbsent:   "app",
		},
		{
			name: "critical — 600ms p99",
			entries: []collector.SyscallEntry{
				{Name: "fsync", Comm: "pg", Latency: collector.Percentiles{P99: 600 * time.Millisecond}, Count: 500},
			},
			wantRule:     "syscall_latency_high",
			wantProcess:  "pg",
			wantSeverity: SeverityCritical,
			wantFinding:  true,
		},
		{
			name: "one past critical threshold — 501ms",
			entries: []collector.SyscallEntry{
				{Name: "fsync", Comm: "db", Latency: collector.Percentiles{P99: 501 * time.Millisecond}, Count: 100},
			},
			wantRule:     "syscall_latency_high",
			wantProcess:  "db",
			wantSeverity: SeverityCritical,
			wantFinding:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signals := &collector.Signals{
				Syscall: &collector.SyscallSnapshot{Entries: tc.entries},
			}
			findings := Evaluate(signals, defaultThresholds())

			if tc.wantFinding {
				found := false
				for _, f := range findings {
					if f.Rule == tc.wantRule && f.Process == tc.wantProcess && f.Severity == tc.wantSeverity {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected %s %s for process=%q, findings: %v", tc.wantSeverity, tc.wantRule, tc.wantProcess, findings)
				}
			} else {
				if bad := findingFor(findings, "syscall_latency_high"); bad != nil {
					t.Errorf("expected no syscall_latency_high finding, got %+v", bad)
				}
			}

			// Verify a process that should NOT trigger the rule
			if tc.wantAbsent != "" {
				for _, f := range findings {
					if f.Rule == tc.wantRule && f.Process == tc.wantAbsent {
						t.Errorf("process=%q should NOT trigger %s", tc.wantAbsent, tc.wantRule)
					}
				}
			}
		})
	}
}

// ─── Syscall error rate ───────────────────────────────────────────────────────

func TestEvaluate_SyscallErrorRate(t *testing.T) {
	tests := []struct {
		name         string
		syscallName  string
		comm         string
		count        uint64
		errorCount   uint64
		wantFinding  bool
		wantSeverity Severity
		wantProcess  string
	}{
		{
			name:        "below threshold — 0.05% error rate",
			syscallName: "read",
			comm:        "app",
			count:       10000,
			errorCount:  5,
			wantFinding: false,
		},
		{
			name:         "exactly at warning threshold",
			syscallName:  "open",
			comm:         "app",
			count:        1000,
			errorCount:   20,
			wantFinding:  true,
			wantSeverity: SeverityWarning,
			wantProcess:  "app",
		},
		{
			name:         "warning — 3% error rate",
			syscallName:  "open",
			comm:         "app",
			count:        1000,
			errorCount:   30,
			wantFinding:  true,
			wantSeverity: SeverityWarning,
			wantProcess:  "app",
		},
		{
			name:         "critical — 15% error rate",
			syscallName:  "connect",
			comm:         "client",
			count:        100,
			errorCount:   15,
			wantFinding:  true,
			wantSeverity: SeverityCritical,
			wantProcess:  "client",
		},
		{
			name:         "one past critical threshold",
			syscallName:  "write",
			comm:         "svc",
			count:        100,
			errorCount:   11,
			wantFinding:  true,
			wantSeverity: SeverityCritical,
			wantProcess:  "svc",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signals := &collector.Signals{
				Syscall: &collector.SyscallSnapshot{
					Entries: []collector.SyscallEntry{
						{Name: tc.syscallName, Comm: tc.comm, Count: tc.count, ErrorCount: tc.errorCount,
							Latency: collector.Percentiles{P99: 1 * time.Millisecond}},
					},
				},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingForSeverity(findings, "syscall_error_rate", tc.wantSeverity)
			if tc.wantFinding {
				if f == nil {
					t.Errorf("expected %s syscall_error_rate finding, got none", tc.wantSeverity)
				} else if tc.wantProcess != "" && f.Process != tc.wantProcess {
					t.Errorf("expected process=%q, got %q", tc.wantProcess, f.Process)
				}
			} else {
				if bad := findingFor(findings, "syscall_error_rate"); bad != nil {
					t.Errorf("expected no syscall_error_rate finding, got %+v", bad)
				}
			}
		})
	}
}

// ─── OOM imminent (memory pressure) ──────────────────────────────────────────

func TestEvaluate_OOMImminent(t *testing.T) {
	tests := []struct {
		name            string
		usedPct         float64
		growthBytesPerS float64
		wantFinding     bool
		wantSeverity    Severity
		wantETA         bool
	}{
		{
			name:        "below threshold — 75%",
			usedPct:     75.0,
			wantFinding: false,
		},
		{
			name:         "warning — 92.5% no growth",
			usedPct:      92.5,
			wantFinding:  true,
			wantSeverity: SeverityWarning,
			wantETA:      false,
		},
		{
			name:            "critical — 96.9% with 50MB/s growth",
			usedPct:         96.9,
			growthBytesPerS: 50_000_000,
			wantFinding:     true,
			wantSeverity:    SeverityCritical,
			wantETA:         true,
		},
		{
			name:        "exactly at warning threshold",
			usedPct:     90.0,
			wantFinding: true,
			wantSeverity: SeverityWarning,
		},
	}

	totalBytes := uint64(16_000_000_000)
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			usedBytes := uint64(float64(totalBytes) * tc.usedPct / 100)
			signals := &collector.Signals{
				Memory: &collector.MemorySnapshot{
					TotalBytes:            totalBytes,
					UsedBytes:             usedBytes,
					UsedPct:               tc.usedPct,
					GrowthRateBytesPerSec: tc.growthBytesPerS,
					AvailableBytes:        totalBytes - usedBytes,
				},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingForSeverity(findings, "oom_imminent", tc.wantSeverity)
			if tc.wantFinding {
				if f == nil {
					t.Errorf("expected %s oom_imminent finding, got none", tc.wantSeverity)
					return
				}
				if tc.wantETA && f.ETA == nil {
					t.Error("expected ETA for oom_imminent with positive growth rate")
				}
			} else {
				if bad := findingFor(findings, "oom_imminent"); bad != nil {
					t.Errorf("expected no oom_imminent finding, got %+v", bad)
				}
			}
		})
	}
}

// ─── Memory limit pressure ────────────────────────────────────────────────────

func TestEvaluate_MemoryLimitPressure(t *testing.T) {
	limit := uint64(4 << 30) // 4 GiB

	tests := []struct {
		name            string
		pod             string
		namespace       string
		usedPct         float64
		growthBytesPerS float64
		wantFinding     bool
		wantSeverity    Severity
		wantProcess     string
		wantETA         bool
		wantNoETA       bool
		wantInTitle     string
	}{
		{
			name:        "below threshold — 70%",
			pod:         "pod-ok",
			usedPct:     70.0,
			wantFinding: false,
		},
		{
			name:         "warning — 88%",
			pod:          "pod-redis",
			usedPct:      88.0,
			wantFinding:  true,
			wantSeverity: SeverityWarning,
			wantProcess:  "pod-redis",
		},
		{
			name:            "critical with ETA — 96% + 7.2 MB/s growth",
			pod:             "pod-kafka",
			usedPct:         96.0,
			growthBytesPerS: 7.2 * 1024 * 1024,
			wantFinding:     true,
			wantSeverity:    SeverityCritical,
			wantProcess:     "pod-kafka",
			wantETA:         true,
		},
		{
			name:            "critical no ETA — 97% + 500 KB/s growth (below 1 MB/s)",
			pod:             "pod-slow",
			usedPct:         97.0,
			growthBytesPerS: 500 * 1024,
			wantFinding:     true,
			wantSeverity:    SeverityCritical,
			wantNoETA:       true,
		},
		{
			name:            "exactly at critical threshold — 95%",
			pod:             "pod-boundary",
			usedPct:         95.0,
			growthBytesPerS: 2 * 1024 * 1024,
			wantFinding:     true,
			wantSeverity:    SeverityCritical,
		},
		{
			name:            "nil cgroup memory — no finding",
			pod:             "",
			usedPct:         0,
			wantFinding:     false,
		},
		{
			name:            "namespace included in title",
			pod:             "kafka-broker-2",
			namespace:       "production",
			usedPct:         96.0,
			growthBytesPerS: 7.2 * 1024 * 1024,
			wantFinding:     true,
			wantSeverity:    SeverityCritical,
			wantInTitle:     "production/kafka-broker-2",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var signals *collector.Signals
			if tc.pod == "" {
				signals = &collector.Signals{}
			} else {
				currentBytes := uint64(float64(limit) * tc.usedPct / 100)
				signals = &collector.Signals{
					CgroupMemory: &collector.CgroupMemorySnapshot{
						Containers: []collector.CgroupMemoryEntry{
							{
								CgroupPath:            "/sys/fs/cgroup/kubepods/" + tc.pod,
								Pod:                   tc.pod,
								Namespace:             tc.namespace,
								LimitBytes:            limit,
								CurrentBytes:          currentBytes,
								UsedPct:               tc.usedPct,
								GrowthRateBytesPerSec: tc.growthBytesPerS,
							},
						},
					},
				}
			}

			findings := Evaluate(signals, defaultThresholds())

			if !tc.wantFinding {
				if bad := findingFor(findings, "memory_limit_pressure"); bad != nil {
					t.Errorf("expected no memory_limit_pressure finding, got %+v", bad)
				}
				return
			}

			f := findingForSeverity(findings, "memory_limit_pressure", tc.wantSeverity)
			if f == nil {
				t.Fatalf("expected %s memory_limit_pressure, got none (findings: %v)", tc.wantSeverity, findings)
			}
			if tc.wantProcess != "" && f.Process != tc.wantProcess {
				t.Errorf("expected Process=%q, got %q", tc.wantProcess, f.Process)
			}
			if tc.wantETA && f.ETA == nil {
				t.Error("expected ETA for critical memory_limit_pressure with growth > 1 MB/s")
			}
			if tc.wantNoETA && f.ETA != nil {
				t.Error("should not compute ETA when growth rate < 1 MB/s")
			}
			if tc.wantInTitle != "" && !containsString(f.Title, tc.wantInTitle) {
				t.Errorf("expected %q in title, got: %q", tc.wantInTitle, f.Title)
			}
		})
	}
}

// ─── Memory high throttling ───────────────────────────────────────────────────

func TestEvaluate_MemoryHighThrottling(t *testing.T) {
	limit := uint64(2 << 30)

	tests := []struct {
		name           string
		pod            string
		usedPct        float64
		highEventRate  float64
		wantFinding    bool
		wantSeverity   Severity
		wantProcess    string
	}{
		{
			name:          "below threshold — 0.5 events/sec",
			pod:           "pod-ok",
			usedPct:       25.0,
			highEventRate: 0.5,
			wantFinding:   false,
		},
		{
			name:          "exactly at threshold — 1.0 events/sec",
			pod:           "pod-edge",
			usedPct:       75.0,
			highEventRate: 1.0,
			wantFinding:   true,
			wantSeverity:  SeverityWarning,
			wantProcess:   "pod-edge",
		},
		{
			name:          "warning — 3.5 events/sec",
			pod:           "pod-throttled",
			usedPct:       82.0,
			highEventRate: 3.5,
			wantFinding:   true,
			wantSeverity:  SeverityWarning,
			wantProcess:   "pod-throttled",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			currentBytes := uint64(float64(limit) * tc.usedPct / 100)
			signals := &collector.Signals{
				CgroupMemory: &collector.CgroupMemorySnapshot{
					Containers: []collector.CgroupMemoryEntry{
						{
							Pod:           tc.pod,
							LimitBytes:    limit,
							CurrentBytes:  currentBytes,
							UsedPct:       tc.usedPct,
							HighBytes:     uint64(float64(limit) * 0.80),
							HighEventRate: tc.highEventRate,
						},
					},
				},
			}
			findings := Evaluate(signals, defaultThresholds())
			f := findingForSeverity(findings, "memory_high_throttling", tc.wantSeverity)
			if tc.wantFinding {
				if f == nil {
					t.Errorf("expected %s memory_high_throttling, got none", tc.wantSeverity)
				} else if tc.wantProcess != "" && f.Process != tc.wantProcess {
					t.Errorf("expected Process=%q, got %q", tc.wantProcess, f.Process)
				}
			} else {
				if bad := findingFor(findings, "memory_high_throttling"); bad != nil {
					t.Errorf("expected no memory_high_throttling finding, got %+v", bad)
				}
			}
		})
	}
}

// ─── RankFindings ─────────────────────────────────────────────────────────────

func TestRankFindings(t *testing.T) {
	eta5m := 5 * time.Minute
	eta30m := 30 * time.Minute

	tests := []struct {
		name     string
		input    []Finding
		wantOrder []string
	}{
		{
			name: "critical with ETA sorted before critical without ETA",
			input: []Finding{
				{Severity: SeverityWarning, Rule: "warn1"},
				{Severity: SeverityCritical, Rule: "crit1", ETA: &eta30m},
				{Severity: SeverityCritical, Rule: "crit2", ETA: &eta5m},
				{Severity: SeverityInfo, Rule: "info1"},
				{Severity: SeverityCritical, Rule: "crit3"},
			},
			wantOrder: []string{"crit2", "crit1", "crit3", "warn1", "info1"},
		},
		{
			name: "all same severity — stable relative order",
			input: []Finding{
				{Severity: SeverityWarning, Rule: "w1"},
				{Severity: SeverityWarning, Rule: "w2"},
			},
			wantOrder: []string{"w1", "w2"},
		},
		{
			name: "single finding unchanged",
			input: []Finding{
				{Severity: SeverityCritical, Rule: "only"},
			},
			wantOrder: []string{"only"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			RankFindings(tc.input)
			for i, want := range tc.wantOrder {
				if i >= len(tc.input) {
					t.Fatalf("findings shorter than expected at position %d", i)
				}
				if tc.input[i].Rule != want {
					t.Errorf("position %d: got %q, want %q", i, tc.input[i].Rule, want)
				}
			}
		})
	}
}

// ─── Multiple findings ordering ───────────────────────────────────────────────

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

	// CRITICAL findings must precede lower-severity ones.
	for i := 1; i < len(findings); i++ {
		if findings[i].Severity > findings[i-1].Severity {
			t.Errorf("findings not sorted: %s at [%d] has higher severity than %s at [%d]",
				findings[i].Rule, i, findings[i-1].Rule, i-1)
		}
	}
}