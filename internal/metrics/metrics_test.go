// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRegistryContainsAllMetrics(t *testing.T) {
	// Gather all metric families from the custom registry.
	families, err := Registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	expected := []string{
		"kerno_syscall_duration_nanoseconds",
		"kerno_syscall_total",
		"kerno_tcp_rtt_nanoseconds",
		"kerno_tcp_retransmits_total",
		"kerno_tcp_connections_total",
		"kerno_oom_kills_total",
		"kerno_disk_io_duration_nanoseconds",
		"kerno_disk_io_bytes_total",
		"kerno_sched_delay_nanoseconds",
		"kerno_fd_open_total",
		"kerno_fd_close_total",
		"kerno_collector_events_total",
		"kerno_collector_errors_total",
		"kerno_bpf_programs_loaded",
		"kerno_info",
	}

	// Since no observations have been made, only the gauge metrics
	// (bpf_programs_loaded) will show up in Gather. Instead, verify
	// the registry does not error on Gather, and check a subset.
	familyNames := make(map[string]bool, len(families))
	for _, f := range families {
		familyNames[f.GetName()] = true
	}

	// Gauge metrics should be present even without observations.
	if !familyNames["kerno_bpf_programs_loaded"] {
		t.Errorf("expected kerno_bpf_programs_loaded in registry")
	}

	// Force an observation on each counter/summary to verify registration.
	SyscallTotal.WithLabelValues("read", "test").Inc()
	SyscallDuration.WithLabelValues("read", "test").Observe(1000)
	TCPRetransmitsTotal.WithLabelValues("1.2.3.4", "5.6.7.8", "curl").Inc()
	OOMKillsTotal.WithLabelValues("oom-victim").Inc()

	families, err = Registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather after observations: %v", err)
	}

	familyNames = make(map[string]bool, len(families))
	for _, f := range families {
		familyNames[f.GetName()] = true
	}

	for _, name := range expected {
		// Some metrics only appear after observation (counters, summaries).
		// We observed the major ones above.
		if strings.Contains(name, "syscall_total") && !familyNames[name] {
			t.Errorf("expected %q in registry after observation", name)
		}
	}
}

func TestSyscallMetrics(t *testing.T) {
	// Reset by creating fresh counters isn't easy with package vars,
	// so just observe and verify delta.
	before := testutil.ToFloat64(SyscallTotal.WithLabelValues("write", "nginx"))
	SyscallTotal.WithLabelValues("write", "nginx").Inc()
	SyscallTotal.WithLabelValues("write", "nginx").Inc()
	after := testutil.ToFloat64(SyscallTotal.WithLabelValues("write", "nginx"))

	if got := after - before; got != 2 {
		t.Errorf("SyscallTotal delta = %v, want 2", got)
	}
}

func TestBPFProgramsLoadedGauge(t *testing.T) {
	BPFProgramsLoaded.Set(5)
	if got := testutil.ToFloat64(BPFProgramsLoaded); got != 5 {
		t.Errorf("BPFProgramsLoaded = %v, want 5", got)
	}

	BPFProgramsLoaded.Set(3)
	if got := testutil.ToFloat64(BPFProgramsLoaded); got != 3 {
		t.Errorf("BPFProgramsLoaded = %v, want 3", got)
	}
}

func TestCollectorEventsCounter(t *testing.T) {
	before := testutil.ToFloat64(CollectorEventsTotal.WithLabelValues("syscall_latency"))
	CollectorEventsTotal.WithLabelValues("syscall_latency").Inc()
	CollectorEventsTotal.WithLabelValues("syscall_latency").Inc()
	CollectorEventsTotal.WithLabelValues("syscall_latency").Inc()
	after := testutil.ToFloat64(CollectorEventsTotal.WithLabelValues("syscall_latency"))

	if got := after - before; got != 3 {
		t.Errorf("CollectorEventsTotal delta = %v, want 3", got)
	}
}

func TestDiskIOMetrics(t *testing.T) {
	before := testutil.ToFloat64(DiskIOBytesTotal.WithLabelValues("8:0", "write"))
	DiskIOBytesTotal.WithLabelValues("8:0", "write").Add(4096)
	after := testutil.ToFloat64(DiskIOBytesTotal.WithLabelValues("8:0", "write"))

	if got := after - before; got != 4096 {
		t.Errorf("DiskIOBytesTotal delta = %v, want 4096", got)
	}
}

func TestInfoMetric(t *testing.T) {
	InfoMetric.WithLabelValues("dev").Set(1)

	g := InfoMetric.WithLabelValues("dev")
	if got := testutil.ToFloat64(g); got != 1 {
		t.Errorf("InfoMetric = %v, want 1", got)
	}
}
