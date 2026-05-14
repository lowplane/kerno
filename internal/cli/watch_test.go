// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"
)

// ─── filterTCPEntries ──────────────────────────────────────────────────────

func TestFilterTCPEntries_NoFilter(t *testing.T) {
	agg := map[tcpConnKey]*tcpConnStats{
		{SAddr: "10.0.0.1", DAddr: "10.0.0.2", SPort: 8080, DPort: 443, Comm: "nginx"}: {
			RTTs:        []time.Duration{1 * time.Millisecond, 2 * time.Millisecond},
			Retransmits: 3,
			EventCount:  5,
		},
		{SAddr: "10.0.0.3", DAddr: "10.0.0.4", SPort: 9090, DPort: 80, Comm: "curl"}: {
			RTTs:        []time.Duration{500 * time.Microsecond},
			Retransmits: 0,
			EventCount:  2,
		},
	}

	entries := filterTCPEntries(agg, watchTCPOpts{})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Should be sorted by retransmits desc.
	if entries[0].Stats.Retransmits != 3 {
		t.Errorf("first entry retransmits = %d, want 3", entries[0].Stats.Retransmits)
	}
}

func TestFilterTCPEntries_RetransmitsOnly(t *testing.T) {
	agg := map[tcpConnKey]*tcpConnStats{
		{Comm: "nginx"}: {
			RTTs:        []time.Duration{1 * time.Millisecond},
			Retransmits: 5,
			EventCount:  10,
		},
		{Comm: "curl"}: {
			RTTs:        []time.Duration{1 * time.Millisecond},
			Retransmits: 0,
			EventCount:  3,
		},
	}

	entries := filterTCPEntries(agg, watchTCPOpts{retransmits: true})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry with retransmits, got %d", len(entries))
	}
	if entries[0].Key.Comm != "nginx" {
		t.Errorf("expected nginx, got %q", entries[0].Key.Comm)
	}
}

func TestFilterTCPEntries_ThresholdRTT(t *testing.T) {
	agg := map[tcpConnKey]*tcpConnStats{
		{Comm: "fast"}: {
			RTTs:       []time.Duration{500 * time.Microsecond},
			EventCount: 1,
		},
		{Comm: "slow"}: {
			RTTs:       []time.Duration{10 * time.Millisecond, 20 * time.Millisecond},
			EventCount: 2,
		},
	}

	entries := filterTCPEntries(agg, watchTCPOpts{thresholdRTT: 5 * time.Millisecond})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry above threshold, got %d", len(entries))
	}
	if entries[0].Key.Comm != "slow" {
		t.Errorf("expected slow, got %q", entries[0].Key.Comm)
	}
}

// ─── computeFDEntries ──────────────────────────────────────────────────────

func TestComputeFDEntries_Basic(t *testing.T) {
	agg := map[fdProcKey]*fdProcStats{
		{PID: 1234, Comm: "leaky"}:  {Opens: 100, Closes: 20},
		{PID: 5678, Comm: "stable"}: {Opens: 50, Closes: 50},
	}

	interval := 5 * time.Second
	threshold := 10.0

	entries := computeFDEntries(agg, interval, threshold)

	// "leaky" has growth rate = (100-20)/5 = 16.0, above threshold.
	// "stable" has growth rate = 0/5 = 0.0, below threshold.
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry above threshold, got %d", len(entries))
	}

	e := entries[0]
	if e.Key.Comm != "leaky" {
		t.Errorf("expected leaky, got %q", e.Key.Comm)
	}
	if e.NetDelta != 80 {
		t.Errorf("NetDelta = %d, want 80", e.NetDelta)
	}
	if e.GrowthRate != 16.0 {
		t.Errorf("GrowthRate = %.1f, want 16.0", e.GrowthRate)
	}
}

func TestComputeFDEntries_AllBelowThreshold(t *testing.T) {
	agg := map[fdProcKey]*fdProcStats{
		{PID: 1, Comm: "a"}: {Opens: 10, Closes: 9},
	}

	entries := computeFDEntries(agg, 5*time.Second, 10.0)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestComputeFDEntries_SortedByGrowthRate(t *testing.T) {
	agg := map[fdProcKey]*fdProcStats{
		{PID: 1, Comm: "slow-leak"}:   {Opens: 60, Closes: 10},
		{PID: 2, Comm: "fast-leak"}:   {Opens: 200, Closes: 10},
		{PID: 3, Comm: "medium-leak"}: {Opens: 100, Closes: 10},
	}

	entries := computeFDEntries(agg, 1*time.Second, 10.0)

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Should be sorted by growth rate descending.
	if entries[0].Key.Comm != "fast-leak" {
		t.Errorf("first = %q, want fast-leak", entries[0].Key.Comm)
	}
	if entries[1].Key.Comm != "medium-leak" {
		t.Errorf("second = %q, want medium-leak", entries[1].Key.Comm)
	}
	if entries[2].Key.Comm != "slow-leak" {
		t.Errorf("third = %q, want slow-leak", entries[2].Key.Comm)
	}
}

// ─── oomEventJSON ──────────────────────────────────────────────────────────

func TestOOMEventJSON(t *testing.T) {
	event := &oomEventOut{
		Victim:       "postgres",
		PID:          1234,
		TriggeredPID: 5678,
		OOMScore:     950,
		RSSPages:     262144,
		TotalPages:   524288,
		RSSBytes:     262144 * 4096,
		TotalBytes:   524288 * 4096,
	}

	if event.RSSBytes != 262144*4096 {
		t.Errorf("RSSBytes = %d, want %d", event.RSSBytes, 262144*4096)
	}
	if event.Victim != "postgres" {
		t.Errorf("Victim = %q, want postgres", event.Victim)
	}
}

// ─── tcpSummaryJSON ────────────────────────────────────────────────────────

func TestTCPSummaryJSON(t *testing.T) {
	entries := []tcpSummaryEntry{
		{
			Key: tcpConnKey{
				SAddr: "10.0.0.1",
				DAddr: "10.0.0.2",
				SPort: 8080,
				DPort: 443,
				Comm:  "nginx",
			},
			Stats: &tcpConnStats{
				RTTs:        []time.Duration{1 * time.Millisecond},
				Retransmits: 3,
				EventCount:  5,
			},
			RTTP50: 1 * time.Millisecond,
			RTTP99: 1 * time.Millisecond,
		},
	}

	out := tcpSummaryJSON(entries, 2*time.Second)

	if len(out.Connections) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(out.Connections))
	}
	conn := out.Connections[0]
	if conn.Comm != "nginx" {
		t.Errorf("Comm = %q, want nginx", conn.Comm)
	}
	if conn.Retransmits != 3 {
		t.Errorf("Retransmits = %d, want 3", conn.Retransmits)
	}
	if conn.SrcPort != 8080 {
		t.Errorf("SrcPort = %d, want 8080", conn.SrcPort)
	}
}
