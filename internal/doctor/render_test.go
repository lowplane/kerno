// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleReport() *Report {
	eta := 5 * time.Minute
	return &Report{
		Hostname:  "prod-db-01",
		KernelVer: "6.8.0-generic",
		Arch:      "x86_64",
		StartTime: time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 3, 21, 12, 0, 30, 0, time.UTC),
		Duration:  30 * time.Second,
		Findings: []Finding{
			{
				Severity: SeverityCritical,
				Rule:     "disk_io_bottleneck",
				Title:    "Disk I/O Bottleneck Detected",
				Signal:   "diskio",
				Cause:    "Storage device is saturated",
				Impact:   "Database writes delayed",
				Evidence: "sync P99=300ms",
				Fix:      []string{"Check IOPS: iostat -x 1 5", "Consider faster storage"},
				Metric:   "disk_sync_p99",
				Value:    300000000,
			},
			{
				Severity: SeverityWarning,
				Rule:     "fd_leak",
				Title:    "File Descriptor Leak Suspected",
				Signal:   "fd",
				Cause:    "FDs opened faster than closed",
				Impact:   "Process will hit ulimit in ~5m",
				Evidence: "growth rate=20.0 FDs/sec",
				Fix:      []string{"Check open FDs: ls /proc/<pid>/fd | wc -l"},
				Metric:   "fd_growth_per_sec",
				Value:    20.0,
				ETA:      &eta,
			},
		},
		EventsCollected: 15000,
	}
}

// ─── PrettyRenderer ────────────────────────────────────────────────────────

func TestPrettyRenderer(t *testing.T) {
	tests := []struct {
		name            string
		report          *Report
		noBanner        bool
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:     "header with findings",
			report:   sampleReport(),
			noBanner: false,
			wantContains: []string{
				"KERNO DOCTOR",
				"Kernel Diagnostic Report",
				"prod-db-01",
				"6.8.0-generic",
				"FINDINGS",
				"1 critical",
				"Disk I/O Bottleneck Detected",
				"File Descriptor Leak Suspected",
				"sync P99=300ms",
				"iostat -x 1 5",
				"SYSTEM SUMMARY",
				"15000",
			},
		},
		{
			name:     "no banner",
			report:   sampleReport(),
			noBanner: true,
			wantContains: []string{
				"FINDINGS",
			},
			wantNotContains: []string{
				"KERNO DOCTOR",
			},
		},
		{
			name: "healthy system",
			report: &Report{
				Duration: 30 * time.Second,
				Findings: []Finding{
					{
						Severity: SeverityInfo,
						Rule:     "healthy_system",
						Title:    "System Healthy",
						Signal:   "all",
						Evidence: "All kernel signals within normal thresholds",
					},
				},
			},
			noBanner: false,
			wantContains: []string{
				"System Healthy",
				"0 critical",
			},
		},
		{
			name: "AI analysis",
			report: func() *Report {
				r := sampleReport()
				r.Analysis = &AnalysisResponse{
					Summary: "Disk saturation is causing cascading latency.",
					Correlations: []Correlation{
						{Signals: []string{"diskio", "syscall"}, Description: "Disk bottleneck causing slow fsync", Confidence: 0.9},
					},
					RootCauses: []RootCause{
						{Description: "NVMe SSD nearing end of life", Fix: "Replace drive"},
					},
				}
				return r
			}(),
			noBanner: false,
			wantContains: []string{
				"AI ANALYSIS",
				"Disk saturation is causing cascading latency",
				"diskio + syscall",
				"NVMe SSD nearing end of life",
			},
		},
		{
			name:     "recommended action order",
			report:   sampleReport(),
			noBanner: false,
			wantContains: []string{
				"RECOMMENDED ACTION ORDER",
				"[NOW]",
			},
		},
		{
			name:     "empty findings",
			report:   &Report{Duration: 10 * time.Second, Findings: nil},
			noBanner: false,
			wantContains: []string{
				"0 critical · 0 warning · 0 info",
			},
			wantNotContains: []string{
				"RECOMMENDED ACTION ORDER",
			},
		},
		{
			name: "single info finding",
			report: &Report{
				Duration: 10 * time.Second,
				Findings: []Finding{
					{
						Severity: SeverityInfo,
						Rule:     "info_finding",
						Title:    "Info Finding Title",
						Signal:   "all",
						Evidence: "All normal",
					},
				},
			},
			noBanner: false,
			wantContains: []string{
				"0 critical · 0 warning · 1 info",
				"Info Finding Title",
			},
		},
		{
			name: "bar ratio below zero clamped",
			report: &Report{
				Duration: 10 * time.Second,
				Findings: []Finding{
					{
						Severity:  SeverityCritical,
						Rule:      "neg_bar",
						Title:     "Negative Bar Finding",
						Signal:    "sig",
						Evidence:  "ev",
						Value:     -10,
						Threshold: 100,
					},
				},
			},
			noBanner: false,
			wantContains: []string{
				"Negative Bar Finding",
			},
			wantNotContains: []string{
				"Limit",
			},
		},
		{
			name: "bar width capped at prBarWidth",
			report: &Report{
				Duration: 10 * time.Second,
				Findings: []Finding{
					{
						Severity:  SeverityCritical,
						Rule:      "cap_bar",
						Title:     "Capped Bar Finding",
						Signal:    "sig",
						Evidence:  "ev",
						Value:     1e9,
						Threshold: 1,
					},
				},
			},
			noBanner: false,
			wantContains: []string{
				"Capped Bar Finding",
				"▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			r := &PrettyRenderer{NoColor: true, NoBanner: tt.noBanner}
			if err := r.Render(&buf, tt.report); err != nil {
				t.Fatalf("Render failed: %v", err)
			}
			output := buf.String()

			for _, check := range tt.wantContains {
				if !strings.Contains(output, check) {
					t.Errorf("pretty output missing %q", check)
				}
			}
			for _, check := range tt.wantNotContains {
				if strings.Contains(output, check) {
					t.Errorf("pretty output should NOT contain %q", check)
				}
			}
		})
	}
}

// ─── JSONRenderer ──────────────────────────────────────────────────────────

func TestJSONRenderer(t *testing.T) {
	tests := []struct {
		name   string
		report *Report
		pretty bool
		check  func(t *testing.T, raw string, jr jsonReport)
	}{
		{
			name:   "pretty valid JSON with summary",
			report: sampleReport(),
			pretty: true,
			check: func(t *testing.T, raw string, jr jsonReport) {
				if jr.Hostname != "prod-db-01" {
					t.Errorf("hostname=%q, want prod-db-01", jr.Hostname)
				}
				if jr.KernelVer != "6.8.0-generic" {
					t.Errorf("kernelVer=%q, want 6.8.0-generic", jr.KernelVer)
				}
				if len(jr.Findings) != 2 {
					t.Errorf("findings=%d, want 2", len(jr.Findings))
				}
				if jr.Summary.Critical != 1 {
					t.Errorf("critical=%d, want 1", jr.Summary.Critical)
				}
				if jr.Summary.Warning != 1 {
					t.Errorf("warning=%d, want 1", jr.Summary.Warning)
				}
				if jr.Summary.EventsCollected != 15000 {
					t.Errorf("eventsCollected=%d, want 15000", jr.Summary.EventsCollected)
				}
			},
		},
		{
			name:   "finding fields and ETA",
			report: sampleReport(),
			pretty: false,
			check: func(t *testing.T, raw string, jr jsonReport) {
				// Check the critical finding.
				f := jr.Findings[0]
				if f.Severity != "CRITICAL" {
					t.Errorf("severity=%q, want CRITICAL", f.Severity)
				}
				if f.Rule != "disk_io_bottleneck" {
					t.Errorf("rule=%q, want disk_io_bottleneck", f.Rule)
				}
				if len(f.Fix) != 2 {
					t.Errorf("fix count=%d, want 2", len(f.Fix))
				}

				// Check the warning finding has ETA.
				w := jr.Findings[1]
				if w.ETA == "" {
					t.Error("warning finding should have ETA")
				}
			},
		},
		{
			name:   "compact is single line",
			report: sampleReport(),
			pretty: false,
			check: func(t *testing.T, raw string, jr jsonReport) {
				// Compact JSON should be a single line (plus trailing newline from Encoder).
				lines := strings.Split(strings.TrimSpace(raw), "\n")
				if len(lines) != 1 {
					t.Errorf("compact JSON should be 1 line, got %d", len(lines))
				}
			},
		},
		{
			name: "AI analysis block",
			report: func() *Report {
				r := sampleReport()
				r.Analysis = &AnalysisResponse{
					Summary: "Test summary",
				}
				return r
			}(),
			pretty: true,
			check: func(t *testing.T, raw string, jr jsonReport) {
				if jr.Analysis == nil {
					t.Error("expected analysis in JSON output")
				}
				if jr.Analysis.Summary != "Test summary" {
					t.Errorf("analysis summary=%q, want 'Test summary'", jr.Analysis.Summary)
				}
			},
		},
		{
			name:   "empty findings",
			report: &Report{Hostname: "test", Duration: 10 * time.Second},
			pretty: true,
			check: func(t *testing.T, raw string, jr jsonReport) {
				if jr.Findings != nil && len(jr.Findings) != 0 {
					t.Errorf("expected nil or empty findings, got %d", len(jr.Findings))
				}
			},
		},
		{
			name: "single finding round-trip",
			report: &Report{
				Hostname: "test",
				Duration: 10 * time.Second,
				Findings: []Finding{
					{
						Severity: SeverityWarning,
						Rule:     "some_warning",
						Title:    "Warning Title",
						Signal:   "sig",
						Evidence: "ev",
					},
				},
			},
			pretty: true,
			check: func(t *testing.T, raw string, jr jsonReport) {
				if len(jr.Findings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(jr.Findings))
				}
				f := jr.Findings[0]
				if f.Severity != "WARNING" {
					t.Errorf("severity=%q, want WARNING", f.Severity)
				}
				if f.Rule != "some_warning" {
					t.Errorf("rule=%q, want some_warning", f.Rule)
				}
				if jr.Summary.Warning != 1 {
					t.Errorf("summary warning=%d, want 1", jr.Summary.Warning)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			r := &JSONRenderer{Pretty: tt.pretty}
			if err := r.Render(&buf, tt.report); err != nil {
				t.Fatalf("Render failed: %v", err)
			}

			var jr jsonReport
			if err := json.Unmarshal(buf.Bytes(), &jr); err != nil {
				t.Fatalf("invalid JSON output: %v", err)
			}

			tt.check(t, buf.String(), jr)
		})
	}
}
