// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"
)

// ─── filterTCPEntries ──────────────────────────────────────────────────────

func TestFilterTCPEntries(t *testing.T) {
	tests := []struct {
		name      string
		agg       map[tcpConnKey]*tcpConnStats
		opts      watchTCPOpts
		wantCount int
		check     func(t *testing.T, entries []tcpSummaryEntry)
	}{
		{
			name: "no filter",
			agg: map[tcpConnKey]*tcpConnStats{
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
			},
			opts:      watchTCPOpts{},
			wantCount: 2,
			check: func(t *testing.T, entries []tcpSummaryEntry) {
				// Should be sorted by retransmits desc.
				if entries[0].Stats.Retransmits != 3 {
					t.Errorf("first entry retransmits = %d, want 3", entries[0].Stats.Retransmits)
				}
			},
		},
		{
			name: "retransmits only",
			agg: map[tcpConnKey]*tcpConnStats{
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
			},
			opts:      watchTCPOpts{retransmits: true},
			wantCount: 1,
			check: func(t *testing.T, entries []tcpSummaryEntry) {
				if entries[0].Key.Comm != "nginx" {
					t.Errorf("expected nginx, got %q", entries[0].Key.Comm)
				}
			},
		},
		{
			name: "threshold RTT",
			agg: map[tcpConnKey]*tcpConnStats{
				{Comm: "fast"}: {
					RTTs:       []time.Duration{500 * time.Microsecond},
					EventCount: 1,
				},
				{Comm: "slow"}: {
					RTTs:       []time.Duration{10 * time.Millisecond, 20 * time.Millisecond},
					EventCount: 2,
				},
			},
			opts:      watchTCPOpts{thresholdRTT: 5 * time.Millisecond},
			wantCount: 1,
			check: func(t *testing.T, entries []tcpSummaryEntry) {
				if entries[0].Key.Comm != "slow" {
					t.Errorf("expected slow, got %q", entries[0].Key.Comm)
				}
			},
		},
		{
			name:      "empty map",
			agg:       map[tcpConnKey]*tcpConnStats{},
			opts:      watchTCPOpts{},
			wantCount: 0,
			check:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			entries := filterTCPEntries(tt.agg, tt.opts)
			if len(entries) != tt.wantCount {
				t.Fatalf("expected %d entries, got %d", tt.wantCount, len(entries))
			}
			if tt.check != nil {
				tt.check(t, entries)
			}
		})
	}
}

// ─── computeFDEntries ──────────────────────────────────────────────────────

func TestComputeFDEntries(t *testing.T) {
	tests := []struct {
		name      string
		agg       map[fdProcKey]*fdProcStats
		interval  time.Duration
		threshold float64
		wantCount int
		check     func(t *testing.T, entries []fdSummaryEntry)
	}{
		{
			name: "basic above threshold",
			agg: map[fdProcKey]*fdProcStats{
				{PID: 1234, Comm: "leaky"}:  {Opens: 100, Closes: 20},
				{PID: 5678, Comm: "stable"}: {Opens: 50, Closes: 50},
			},
			interval:  5 * time.Second,
			threshold: 10.0,
			wantCount: 1,
			check: func(t *testing.T, entries []fdSummaryEntry) {
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
			},
		},
		{
			name: "all below threshold",
			agg: map[fdProcKey]*fdProcStats{
				{PID: 1, Comm: "a"}: {Opens: 10, Closes: 9},
			},
			interval:  5 * time.Second,
			threshold: 10.0,
			wantCount: 0,
			check:     nil,
		},
		{
			name: "sorted by growth rate",
			agg: map[fdProcKey]*fdProcStats{
				{PID: 1, Comm: "slow-leak"}:   {Opens: 60, Closes: 10},
				{PID: 2, Comm: "fast-leak"}:   {Opens: 200, Closes: 10},
				{PID: 3, Comm: "medium-leak"}: {Opens: 100, Closes: 10},
			},
			interval:  1 * time.Second,
			threshold: 10.0,
			wantCount: 3,
			check: func(t *testing.T, entries []fdSummaryEntry) {
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
			},
		},
		{
			name: "single entry at threshold",
			agg: map[fdProcKey]*fdProcStats{
				{PID: 42, Comm: "boundary"}: {Opens: 55, Closes: 5},
			},
			interval:  5 * time.Second,
			threshold: 10.0,
			wantCount: 1,
			check: func(t *testing.T, entries []fdSummaryEntry) {
				if entries[0].GrowthRate != 10.0 {
					t.Errorf("GrowthRate = %.1f, want 10.0", entries[0].GrowthRate)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			entries := computeFDEntries(tt.agg, tt.interval, tt.threshold)
			if len(entries) != tt.wantCount {
				t.Fatalf("expected %d entries, got %d", tt.wantCount, len(entries))
			}
			if tt.check != nil {
				tt.check(t, entries)
			}
		})
	}
}

// ─── oomEventJSON ──────────────────────────────────────────────────────────

func TestOOMEventJSON(t *testing.T) {
	tests := []struct {
		name  string
		event *oomEventOut
		check func(t *testing.T, event *oomEventOut)
	}{
		{
			name: "struct fields",
			event: &oomEventOut{
				Victim:       "postgres",
				PID:          1234,
				TriggeredPID: 5678,
				OOMScore:     950,
				RSSPages:     262144,
				TotalPages:   524288,
				RSSBytes:     262144 * 4096,
				TotalBytes:   524288 * 4096,
			},
			check: func(t *testing.T, event *oomEventOut) {
				if event.RSSBytes != 262144*4096 {
					t.Errorf("RSSBytes = %d, want %d", event.RSSBytes, 262144*4096)
				}
				if event.Victim != "postgres" {
					t.Errorf("Victim = %q, want postgres", event.Victim)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.check(t, tt.event)
		})
	}
}

// ─── tcpSummaryJSON ────────────────────────────────────────────────────────

func TestTCPSummaryJSON(t *testing.T) {
	tests := []struct {
		name     string
		entries  []tcpSummaryEntry
		interval time.Duration
		check    func(t *testing.T, out tcpSummaryJSONOut)
	}{
		{
			name: "single connection",
			entries: []tcpSummaryEntry{
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
			},
			interval: 2 * time.Second,
			check: func(t *testing.T, out tcpSummaryJSONOut) {
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := tcpSummaryJSON(tt.entries, tt.interval)
			tt.check(t, out)
		})
	}
}
