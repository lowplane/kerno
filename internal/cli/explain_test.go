// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/optiqor/kerno/internal/doctor"
)

func TestLookupRule_ValidNames(t *testing.T) {
	tests := []struct {
		name           string
		wantSignal     string
		wantSeverity   string
		wantTrigger    string
	}{
		{
			name:         "oom_imminent",
			wantSignal:   "memory",
			wantSeverity: "CRITICAL / WARNING",
			wantTrigger:  "memory.UsedPct > 90",
		},
		{
			name:         "fd_leak",
			wantSignal:   "fd",
			wantSeverity: "WARNING",
			wantTrigger:  "FD growth rate",
		},
		{
			name:         "tcp_retransmit_storm",
			wantSignal:   "tcp",
			wantSeverity: "CRITICAL",
			wantTrigger:  "retransmit rate",
		},
		{
			name:         "healthy_system",
			wantSignal:   "all",
			wantSeverity: "INFO",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := doctor.LookupRule(tt.name)
			if err != nil {
				t.Fatalf("LookupRule(%q) returned unexpected error: %v", tt.name, err)
			}
			if info.Name != tt.name {
				t.Errorf("Name: got %q, want %q", info.Name, tt.name)
			}
			if info.Signal != tt.wantSignal {
				t.Errorf("Signal: got %q, want %q", info.Signal, tt.wantSignal)
			}
			if !strings.Contains(info.Severity, tt.wantSeverity) {
				t.Errorf("Severity: got %q, want it to contain %q", info.Severity, tt.wantSeverity)
			}
			if tt.wantTrigger != "" && !strings.Contains(info.Trigger, tt.wantTrigger) {
				t.Errorf("Trigger: got %q, want it to contain %q", info.Trigger, tt.wantTrigger)
			}
			if len(info.Fix) == 0 {
				t.Errorf("Fix: expected at least one fix step, got none")
			}
		})
	}
}

func TestLookupRule_InvalidName(t *testing.T) {
	_, err := doctor.LookupRule("does_not_exist")
	if err == nil {
		t.Fatal("LookupRule(\"does_not_exist\") expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown rule") {
		t.Errorf("error message should contain 'unknown rule', got: %v", err)
	}
}

func TestLookupRule_Suggestion(t *testing.T) {
	_, err := doctor.LookupRule("oom")
	if err == nil {
		t.Fatal("expected error for partial name, got nil")
	}
	// Should suggest something oom-related
	if !strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("expected 'Did you mean' suggestion, got: %v", err)
	}
}

func TestPrintRuleDoc_ContainsFields(t *testing.T) {
	info, err := doctor.LookupRule("oom_imminent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	doc := doctor.PrintRuleDoc(info)

	for _, want := range []string{"RULE", "SIGNAL", "SEVERITY", "TRIGGER", "WHY", "FIX", "PAIRS WITH"} {
		if !strings.Contains(doc, want) {
			t.Errorf("PrintRuleDoc output missing field %q", want)
		}
	}
}

func TestRuleNames_NotEmpty(t *testing.T) {
	names := doctor.RuleNames()
	if len(names) == 0 {
		t.Fatal("RuleNames() returned empty list")
	}
}
