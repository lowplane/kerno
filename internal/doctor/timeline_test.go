// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
)

func TestBuildTimeline_LinearCascade(t *testing.T) {
	thresholds := config.Default().Doctor.Thresholds
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	// Step 1: Disk latency spiked at T=0
	// Step 2: Syscall latency climbed at T+8s
	// Step 3: TCP retransmits hit 5% at T+13s
	snap1 := &collector.Signals{
		Timestamp: now,
		DiskIO: &collector.DiskIOSnapshot{
			SyncLatency: collector.Percentiles{P99: 300 * time.Millisecond}, // Threshold is 200ms
			TotalSyncs:  100,
		},
	}
	snap2 := &collector.Signals{
		Timestamp: now.Add(8 * time.Second),
		DiskIO: &collector.DiskIOSnapshot{
			SyncLatency: collector.Percentiles{P99: 300 * time.Millisecond},
		},
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "fsync", Latency: collector.Percentiles{P99: 600 * time.Millisecond}}, // Threshold is 500ms
			},
		},
	}
	snap3 := &collector.Signals{
		Timestamp: now.Add(13 * time.Second),
		DiskIO: &collector.DiskIOSnapshot{
			SyncLatency: collector.Percentiles{P99: 300 * time.Millisecond},
		},
		Syscall: &collector.SyscallSnapshot{
			Entries: []collector.SyscallEntry{
				{Name: "fsync", Latency: collector.Percentiles{P99: 600 * time.Millisecond}},
			},
		},
		TCP: &collector.TCPSnapshot{
			RetransmitRate: 5.0, // Threshold is 2.0%
		},
	}

	history := []*collector.Signals{snap1, snap2, snap3}

	// findings at current snapshot (snap3)
	findings := []Finding{
		{
			Severity:  SeverityCritical,
			Rule:      "disk_io_bottleneck",
			Title:     "Disk I/O Bottleneck Detected",
			Signal:    "diskio",
			Metric:    "disk_sync_p99",
			Threshold: float64(thresholds.DiskP99CriticalNs),
			FiredAt:   snap3.Timestamp,
		},
		{
			Severity:  SeverityCritical,
			Rule:      "syscall_latency_high",
			Title:     "High Syscall Latency",
			Signal:    "syscall",
			Metric:    "syscall_p99_max",
			Threshold: float64(thresholds.SyscallP99CriticalNs),
			FiredAt:   snap3.Timestamp,
		},
		{
			Severity:  SeverityCritical,
			Rule:      "tcp_retransmit_storm",
			Title:     "TCP Retransmit Storm",
			Signal:    "tcp",
			Metric:    "tcp_retransmit_pct",
			Threshold: thresholds.TCPRetransmitPct,
			FiredAt:   snap3.Timestamp,
		},
	}

	timeline := BuildTimeline(findings, history, thresholds)

	if len(timeline.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(timeline.Events))
	}

	// Verify events are sorted by first fired timestamp oldest first.
	if timeline.Events[0].Signal != "diskio" {
		t.Errorf("expected first event to be diskio, got %s", timeline.Events[0].Signal)
	}
	if timeline.Events[1].Signal != "syscall" {
		t.Errorf("expected second event to be syscall, got %s", timeline.Events[1].Signal)
	}
	if timeline.Events[2].Signal != "tcp" {
		t.Errorf("expected third event to be tcp, got %s", timeline.Events[2].Signal)
	}

	// Check resolved fired times.
	if !timeline.Events[0].FiredAt.Equal(snap1.Timestamp) {
		t.Errorf("diskio should have fired at T+0, got %s", timeline.Events[0].FiredAt)
	}
	if !timeline.Events[1].FiredAt.Equal(snap2.Timestamp) {
		t.Errorf("syscall should have fired at T+8, got %s", timeline.Events[1].FiredAt)
	}
	if !timeline.Events[2].FiredAt.Equal(snap3.Timestamp) {
		t.Errorf("tcp should have fired at T+13, got %s", timeline.Events[2].FiredAt)
	}

	// Check causal links.
	// diskio -> syscall (8s gap, maxGap=10s, gap > maxGap/2 triggers decay: 0.85 * (1 - 8/10) = 0.17. Wait, 0.17 < 0.7 so it's filtered out!)
	// Wait, syscall -> tcp (5s gap, maxGap=15s. gap <= maxGap/2 (7.5s) -> no decay -> confidence is 0.80 >= 0.7 -> rendered!)
	if len(timeline.Links) != 1 {
		t.Fatalf("expected 1 causal link, got %d", len(timeline.Links))
	}
	link := timeline.Links[0]
	if link.CauseSignal != "syscall" || link.EffectSignal != "tcp" {
		t.Errorf("expected link syscall->tcp, got %s->%s", link.CauseSignal, link.EffectSignal)
	}
	if link.Confidence != 0.80 {
		t.Errorf("expected confidence 0.80, got %f", link.Confidence)
	}
	if link.GapMs != 5000 {
		t.Errorf("expected gap 5000ms, got %d", link.GapMs)
	}
}

func TestBuildTimeline_ParallelUnrelated(t *testing.T) {
	thresholds := config.Default().Doctor.Thresholds
	now := time.Now()

	findings := []Finding{
		{
			Severity:  SeverityWarning,
			Rule:      "fd_leak",
			Title:     "File Descriptor Leak Suspected",
			Signal:    "fd",
			Metric:    "fd_growth_per_sec",
			Threshold: thresholds.FDGrowthPerSec,
			FiredAt:   now,
		},
		{
			Severity:  SeverityCritical,
			Rule:      "tcp_retransmit_storm",
			Title:     "TCP Retransmit Storm",
			Signal:    "tcp",
			Metric:    "tcp_retransmit_pct",
			Threshold: thresholds.TCPRetransmitPct,
			FiredAt:   now.Add(5 * time.Second),
		},
	}

	timeline := BuildTimeline(findings, nil, thresholds)
	if len(timeline.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(timeline.Events))
	}
	if len(timeline.Links) != 0 {
		t.Errorf("expected 0 links for unrelated findings, got %d", len(timeline.Links))
	}
}

func TestBuildTimeline_SingleFinding(t *testing.T) {
	thresholds := config.Default().Doctor.Thresholds
	now := time.Now()

	findings := []Finding{
		{
			Severity: SeverityCritical,
			Rule:     "oom_kill_occurred",
			Title:    "OOM Kill Detected",
			Signal:   "oom",
			Metric:   "oom_kills",
			FiredAt:  now,
		},
	}

	timeline := BuildTimeline(findings, nil, thresholds)
	if len(timeline.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(timeline.Events))
	}
	if len(timeline.Links) != 0 {
		t.Errorf("expected 0 links for single finding, got %d", len(timeline.Links))
	}
}

func TestBuildTimeline_NoFindings(t *testing.T) {
	thresholds := config.Default().Doctor.Thresholds
	timeline := BuildTimeline(nil, nil, thresholds)
	if timeline == nil {
		t.Fatal("expected non-nil timeline")
	}
	if len(timeline.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(timeline.Events))
	}
	if len(timeline.Links) != 0 {
		t.Errorf("expected 0 links, got %d", len(timeline.Links))
	}
}

func TestBuildTimeline_ConfidenceDecay(t *testing.T) {
	thresholds := config.Default().Doctor.Thresholds
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	// memory -> oom has maxGap = 120s, baseConf = 0.90
	// Test with gap = 15s (<= maxGap/2 (60s) -> no decay)
	findings1 := []Finding{
		{
			Severity:  SeverityWarning,
			Rule:      "oom_imminent",
			Title:     "OOM Imminent",
			Signal:    "memory",
			Metric:    "memory_used_pct",
			Threshold: thresholds.OOMMemoryPct,
			FiredAt:   now,
		},
		{
			Severity: SeverityCritical,
			Rule:     "oom_kill_occurred",
			Title:    "OOM Kill",
			Signal:   "oom",
			Metric:   "oom_kills",
			FiredAt:  now.Add(15 * time.Second),
		},
	}

	tl1 := BuildTimeline(findings1, nil, thresholds)
	if len(tl1.Links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(tl1.Links))
	}
	if tl1.Links[0].Confidence != 0.90 {
		t.Errorf("expected full base confidence 0.90, got %f", tl1.Links[0].Confidence)
	}

	// Test with gap = 100s (> 60s -> decays: 0.90 * (1 - 100/120) = 0.15 < 0.7 -> filtered out)
	findings2 := []Finding{
		{
			Severity:  SeverityWarning,
			Rule:      "oom_imminent",
			Title:     "OOM Imminent",
			Signal:    "memory",
			Metric:    "memory_used_pct",
			Threshold: thresholds.OOMMemoryPct,
			FiredAt:   now,
		},
		{
			Severity: SeverityCritical,
			Rule:     "oom_kill_occurred",
			Title:    "OOM Kill",
			Signal:   "oom",
			Metric:   "oom_kills",
			FiredAt:  now.Add(100 * time.Second),
		},
	}

	tl2 := BuildTimeline(findings2, nil, thresholds)
	if len(tl2.Links) != 0 {
		t.Errorf("expected link to decay and be filtered out, got %d links", len(tl2.Links))
	}
}
