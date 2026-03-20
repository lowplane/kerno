// Copyright 2026 Lowplane contributors
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

func TestPrettyRenderer_ContainsHeader(t *testing.T) {
	var buf bytes.Buffer
	r := &PrettyRenderer{NoColor: true}
	report := sampleReport()

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()

	checks := []string{
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
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("pretty output missing %q", check)
		}
	}
}

func TestPrettyRenderer_HealthySystem(t *testing.T) {
	var buf bytes.Buffer
	r := &PrettyRenderer{NoColor: true}
	report := &Report{
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
	}

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "System Healthy") {
		t.Error("pretty output missing 'System Healthy'")
	}
	if !strings.Contains(output, "0 critical") {
		t.Error("pretty output should show 0 critical findings")
	}
}

func TestPrettyRenderer_AIAnalysis(t *testing.T) {
	var buf bytes.Buffer
	r := &PrettyRenderer{NoColor: true}
	report := sampleReport()
	report.Analysis = &AnalysisResponse{
		Summary: "Disk saturation is causing cascading latency.",
		Correlations: []Correlation{
			{Signals: []string{"diskio", "syscall"}, Description: "Disk bottleneck causing slow fsync", Confidence: 0.9},
		},
		RootCauses: []RootCause{
			{Description: "NVMe SSD nearing end of life", Fix: "Replace drive"},
		},
	}

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	checks := []string{
		"AI ANALYSIS",
		"Disk saturation is causing cascading latency",
		"diskio + syscall",
		"NVMe SSD nearing end of life",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("AI analysis output missing %q", check)
		}
	}
}

func TestPrettyRenderer_RecommendedActionOrder(t *testing.T) {
	var buf bytes.Buffer
	r := &PrettyRenderer{NoColor: true}
	report := sampleReport()

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "RECOMMENDED ACTION ORDER") {
		t.Error("pretty output missing RECOMMENDED ACTION ORDER section")
	}
	if !strings.Contains(output, "[NOW]") {
		t.Error("pretty output missing [NOW] urgency for critical finding")
	}
}

func TestJSONRenderer_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONRenderer{Pretty: true}
	report := sampleReport()

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var jr jsonReport
	if err := json.Unmarshal(buf.Bytes(), &jr); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

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
}

func TestJSONRenderer_FindingFields(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONRenderer{Pretty: false}
	report := sampleReport()

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var jr jsonReport
	if err := json.Unmarshal(buf.Bytes(), &jr); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

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
}

func TestJSONRenderer_Compact(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONRenderer{Pretty: false}
	report := sampleReport()

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	// Compact JSON should be a single line (plus trailing newline from Encoder).
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("compact JSON should be 1 line, got %d", len(lines))
	}
}

func TestJSONRenderer_WithAIAnalysis(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONRenderer{Pretty: true}
	report := sampleReport()
	report.Analysis = &AnalysisResponse{
		Summary: "Test summary",
	}

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var jr jsonReport
	if err := json.Unmarshal(buf.Bytes(), &jr); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if jr.Analysis == nil {
		t.Error("expected analysis in JSON output")
	}
	if jr.Analysis.Summary != "Test summary" {
		t.Errorf("analysis summary=%q, want 'Test summary'", jr.Analysis.Summary)
	}
}

func TestJSONRenderer_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONRenderer{Pretty: true}
	report := &Report{
		Hostname: "test",
		Duration: 10 * time.Second,
	}

	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var jr jsonReport
	if err := json.Unmarshal(buf.Bytes(), &jr); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if jr.Findings != nil && len(jr.Findings) != 0 {
		t.Errorf("expected nil or empty findings, got %d", len(jr.Findings))
	}
}
