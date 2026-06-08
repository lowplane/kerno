// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package doctor implements the kerno doctor diagnostic engine.
//
// The engine collects kernel signals via eBPF, evaluates them against
// configurable threshold rules, ranks findings by severity, and renders
// human-readable reports. An optional AI analyzer can enrich findings
// with cross-signal correlation and root cause analysis.
package doctor

import (
	"fmt"
	"sort"
	"time"
)

// Severity represents the severity level of a diagnostic finding.
type Severity int

const (
	// SeverityInfo indicates an informational finding with no action needed.
	SeverityInfo Severity = iota
	// SeverityWarning indicates a potential issue that should be investigated.
	SeverityWarning
	// SeverityCritical indicates a severe issue requiring immediate action.
	SeverityCritical
)

// String returns the human-readable severity label.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Icon returns the severity icon for terminal output.
func (s Severity) Icon() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARN"
	case SeverityCritical:
		return "CRIT"
	default:
		return "????"
	}
}

// Finding represents a single diagnostic finding produced by a rule.
type Finding struct {
	// Severity is the urgency level: CRITICAL, WARNING, or INFO.
	Severity Severity

	// Rule identifies which diagnostic rule produced this finding.
	Rule string

	// Title is a short human-readable summary (e.g., "Disk I/O Bottleneck Detected").
	Title string

	// Signal names the eBPF signal type that triggered this finding.
	Signal string

	// Cause explains in plain language why this is happening.
	Cause string

	// Impact describes what is breaking because of this issue.
	Impact string

	// Evidence provides the raw metric data supporting the finding.
	Evidence string

	// Fix contains actionable remediation steps.
	Fix []string

	// ETA is the estimated time until the situation worsens (e.g., until OOM kill).
	// Nil if not applicable.
	ETA *time.Duration

	// Metric is the specific metric name that triggered the rule.
	Metric string

	// Value is the observed metric value.
	Value float64

	// Threshold is the configured threshold that was breached.
	Threshold float64

	// Process is the relevant process name, if applicable.
	Process string

	// FiredAt is the wall-clock time when the underlying metric first crossed
	// its threshold in the history ring buffer. Zero value means "current
	// snapshot only" (no history available yet).
	FiredAt time.Time
}

// ETAString returns a human-readable ETA string, or empty if no ETA.
func (f *Finding) ETAString() string {
	if f.ETA == nil {
		return ""
	}
	d := *f.ETA
	if d < time.Minute {
		return fmt.Sprintf("~%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("~%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("~%dh", int(d.Hours()))
}

// Report is the complete output of a doctor diagnostic run.
type Report struct {
	// Host identifies the machine analyzed.
	Hostname  string
	KernelVer string
	Arch      string

	// Timing records the analysis window.
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration

	// Findings are the ranked diagnostic results.
	Findings []Finding

	// Timeline is the causal sequence for this report.
	Timeline *Timeline

	// Stats tracks collection metadata.
	EventsCollected uint64
	ProgramsLoaded  int

	// Analysis is the optional AI-enhanced analysis (nil if AI disabled).
	Analysis any

	// Signals is the raw signal snapshot the rules were evaluated against.
	// Populated for debug/observability — JSON renderer emits it under
	// the "signals" key so operators can verify thresholds against
	// observed values. Pretty renderer ignores it.
	Signals any `json:"-"`

	// Environment describes how kerno is running (kubernetes, systemd,
	// baremetal). Used by the pretty renderer to add context to the
	// header so an operator immediately sees "this report is for the
	// kerno DaemonSet pod on prod-node-7" vs "this is a bare metal box".
	Environment string

	// LoadFailures lists eBPF programs that could not be loaded during
	// this run. The pretty renderer surfaces these as a single
	// "DEGRADATION" panel rather than letting individual WARN log lines
	// scatter through the output. Empty when everything loaded.
	LoadFailures []LoadFailure
}

// LoadFailure describes one eBPF program that failed to load. The
// renderer presents these aggregated, with a single actionable hint
// (re-run with sudo, install BTF, etc.) instead of a scroll of warns.
type LoadFailure struct {
	Program string `json:"program"`
	Error   string `json:"error"`
	// Hint is a one-line "what to fix" suggestion derived from the
	// error class (permission denied → "re-run with sudo", missing BTF
	// → "kernel needs CONFIG_DEBUG_INFO_BTF", …).
	Hint string `json:"hint,omitempty"`
}

// CountBySeverity returns the number of findings at each severity level.
func (r *Report) CountBySeverity() (critical, warning, info int) {
	for i := range r.Findings {
		switch r.Findings[i].Severity {
		case SeverityCritical:
			critical++
		case SeverityWarning:
			warning++
		case SeverityInfo:
			info++
		}
	}
	return
}

// HasCritical returns true if any finding is CRITICAL.
func (r *Report) HasCritical() bool {
	for i := range r.Findings {
		if r.Findings[i].Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// RankFindings sorts findings by severity DESC, then by ETA ASC (most urgent first),
// then by value/threshold ratio DESC (most exceeded first).
func RankFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		// Higher severity first.
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		// If both have ETAs, most urgent (shortest ETA) first.
		if findings[i].ETA != nil && findings[j].ETA != nil {
			return *findings[i].ETA < *findings[j].ETA
		}
		// Findings with ETA before those without.
		if findings[i].ETA != nil {
			return true
		}
		if findings[j].ETA != nil {
			return false
		}
		// Higher threshold breach ratio first.
		ri := thresholdRatio(findings[i])
		rj := thresholdRatio(findings[j])
		return ri > rj
	})
}

func thresholdRatio(f Finding) float64 {
	if f.Threshold == 0 {
		return 0
	}
	return f.Value / f.Threshold
}
