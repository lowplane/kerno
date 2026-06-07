// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"encoding/json"
	"testing"
)

func TestFilterCriticalFindings_Basic(t *testing.T) {
	tests := []struct {
		name        string
		input       []Finding
		wantLen     int
		wantAllCrit bool
	}{
		{
			name:        "nil input",
			input:       nil,
			wantLen:     0,
			wantAllCrit: true,
		},
		{
			name:        "empty slice",
			input:       []Finding{},
			wantLen:     0,
			wantAllCrit: true,
		},
		{
			name: "all critical",
			input: []Finding{
				{Severity: SeverityCritical, Title: "C1"},
				{Severity: SeverityCritical, Title: "C2"},
			},
			wantLen:     2,
			wantAllCrit: true,
		},
		{
			name: "mixed severities",
			input: []Finding{
				{Severity: SeverityCritical, Title: "Critical"},
				{Severity: SeverityWarning, Title: "Warning"},
				{Severity: SeverityInfo, Title: "Info"},
				{Severity: SeverityCritical, Title: "Critical2"},
			},
			wantLen:     2,
			wantAllCrit: true,
		},
		{
			name: "no critical",
			input: []Finding{
				{Severity: SeverityWarning, Title: "W1"},
				{Severity: SeverityWarning, Title: "W2"},
				{Severity: SeverityInfo, Title: "I1"},
			},
			wantLen:     0,
			wantAllCrit: true,
		},
		{
			name: "single critical",
			input: []Finding{
				{Severity: SeverityInfo, Title: "Info"},
				{Severity: SeverityCritical, Title: "Crit"},
				{Severity: SeverityWarning, Title: "Warn"},
			},
			wantLen:     1,
			wantAllCrit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterCriticalFindings(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("len(got)=%d, want %d", len(got), tt.wantLen)
			}
			if tt.wantAllCrit {
				for i, f := range got {
					if f.Severity != SeverityCritical {
						t.Errorf("got[%d].Severity=%v, want CRITICAL", i, f.Severity)
					}
				}
			}

			if len(got) == 0 && got == nil {
				t.Error("got nil for empty filter result; should return []Finding{}")
			}
		})
	}
}

func TestFilterCriticalFindings_PreservesOrder(t *testing.T) {
	input := []Finding{
		{Severity: SeverityCritical, Rule: "rule_A"},
		{Severity: SeverityWarning, Rule: "rule_W"},
		{Severity: SeverityCritical, Rule: "rule_B"},
		{Severity: SeverityInfo, Rule: "rule_I"},
		{Severity: SeverityCritical, Rule: "rule_C"},
	}

	got := FilterCriticalFindings(input)

	if len(got) != 3 {
		t.Fatalf("len(got)=%d, want 3", len(got))
	}

	rules := []string{"rule_A", "rule_B", "rule_C"}
	for i, f := range got {
		if f.Rule != rules[i] {
			t.Errorf("got[%d].Rule=%q, want %q (order not preserved)", i, f.Rule, rules[i])
		}
	}
}

func TestFilterCriticalFindings_MemoryEfficiency(t *testing.T) {
	input := make([]Finding, 1000)
	for i := range input {
		if i%100 == 0 {
			input[i].Severity = SeverityCritical
		} else {
			input[i].Severity = SeverityWarning
		}
	}

	got := FilterCriticalFindings(input)

	if len(got) != 10 {
		t.Errorf("len(got)=%d, want 10", len(got))
	}
	if cap(got) > 100 {
		t.Logf("warning: capacity=%d for 10 items (may indicate over-allocation)", cap(got))
	}
}

func TestReportHasCriticalAfterFilter(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{
			name: "critical exists after filter",
			findings: []Finding{
				{Severity: SeverityCritical},
				{Severity: SeverityWarning},
			},
			want: true,
		},
		{
			name: "no critical after filter",
			findings: []Finding{
				{Severity: SeverityWarning},
				{Severity: SeverityInfo},
			},
			want: false,
		},
		{
			name:     "empty after filter",
			findings: []Finding{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterCriticalFindings(tt.findings)
			report := &Report{Findings: filtered}

			if got := report.HasCritical(); got != tt.want {
				t.Errorf("HasCritical()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestReportCountBySeverityAfterFilter(t *testing.T) {
	original := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityWarning},
		{Severity: SeverityWarning},
		{Severity: SeverityInfo},
	}

	// After filter
	filtered := FilterCriticalFindings(original)
	report := &Report{Findings: filtered}

	crit, warn, info := report.CountBySeverity()

	if crit != 2 || warn != 0 || info != 0 {
		t.Errorf("CountBySeverity()=(%d,%d,%d), want (2,0,0)", crit, warn, info)
	}
}

func TestFilterCriticalFindings_Performance(t *testing.T) {
	input := make([]Finding, 10000)
	for i := range input {
		if i%1000 == 0 {
			input[i].Severity = SeverityCritical
		} else {
			input[i].Severity = SeverityWarning
		}
	}

	got := FilterCriticalFindings(input)

	if len(got) != 10 {
		t.Errorf("len(got)=%d, want 10", len(got))
	}
}

func TestFilterCriticalFindings_JSONMarshal(t *testing.T) {
	input := []Finding{
		{Severity: SeverityWarning, Title: "Warning"},
		{Severity: SeverityInfo, Title: "Info"},
	}

	filtered := FilterCriticalFindings(input)
	report := &Report{Findings: filtered}
	data, err := json.Marshal(report.Findings)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	if string(data) == "null" {
		t.Error("JSON marshaled to null; should be []")
	}
	if string(data) != "[]" {
		t.Errorf("JSON=%s, want []", string(data))
	}
}
