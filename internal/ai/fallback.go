// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/lowplane/kerno/internal/doctor"
)

// FallbackAnalyzer generates template-driven English summaries from findings
// without calling any LLM. Used when AI is disabled or the provider is unreachable.
type FallbackAnalyzer struct{}

// NewFallbackAnalyzer creates a FallbackAnalyzer.
func NewFallbackAnalyzer() *FallbackAnalyzer {
	return &FallbackAnalyzer{}
}

// Analyze generates a deterministic summary from findings using templates.
func (f *FallbackAnalyzer) Analyze(_ context.Context, req doctor.AnalysisRequest) (*doctor.AnalysisResponse, error) {
	if len(req.Findings) == 0 {
		return &doctor.AnalysisResponse{
			Summary: "All kernel signals are within normal thresholds. No issues detected.",
		}, nil
	}

	// Count severities.
	var critical, warning, info int
	for _, finding := range req.Findings {
		switch finding.Severity {
		case doctor.SeverityCritical:
			critical++
		case doctor.SeverityWarning:
			warning++
		case doctor.SeverityInfo:
			info++
		}
	}

	// Build summary.
	var summary strings.Builder
	if critical > 0 {
		fmt.Fprintf(&summary, "Found %d critical issue(s) requiring immediate attention. ", critical)
	}
	if warning > 0 {
		fmt.Fprintf(&summary, "Found %d warning(s) that should be investigated. ", warning)
	}
	if info > 0 {
		fmt.Fprintf(&summary, "%d informational finding(s). ", info)
	}

	// Add top finding details.
	top := req.Findings[0] // Already ranked by severity.
	fmt.Fprintf(&summary, "The most urgent issue is: %s — %s", top.Title, top.Cause)
	if top.ETA != nil {
		fmt.Fprintf(&summary, " (ETA to failure: %s)", top.ETAString())
	}
	summary.WriteString(".")

	// Build correlations from co-occurring signals.
	correlations := detectSimpleCorrelations(req.Findings)

	// Build root causes from critical findings.
	var rootCauses []doctor.RootCause
	for _, finding := range req.Findings {
		if finding.Severity >= doctor.SeverityWarning {
			fix := ""
			if len(finding.Fix) > 0 {
				fix = finding.Fix[0]
			}
			rootCauses = append(rootCauses, doctor.RootCause{
				Description: finding.Cause,
				Severity:    finding.Severity,
				Fix:         fix,
				Confidence:  1.0, // Deterministic — full confidence.
			})
		}
	}

	return &doctor.AnalysisResponse{
		Summary:      summary.String(),
		Correlations: correlations,
		RootCauses:   rootCauses,
	}, nil
}

// detectSimpleCorrelations looks for common signal co-occurrence patterns.
func detectSimpleCorrelations(findings []doctor.Finding) []doctor.Correlation {
	signals := make(map[string]bool)
	for _, f := range findings {
		signals[f.Signal] = true
	}

	var correlations []doctor.Correlation

	// Disk I/O + syscall latency → likely disk bottleneck causing slow syscalls.
	if signals["diskio"] && signals["syscall"] {
		correlations = append(correlations, doctor.Correlation{
			Signals:     []string{"diskio", "syscall"},
			Description: "High disk I/O latency is likely causing elevated syscall latency for I/O-bound operations (write, fsync, read).",
			Confidence:  0.85,
		})
	}

	// TCP + syscall → network-related syscall slowdown.
	if signals["tcp"] && signals["syscall"] {
		correlations = append(correlations, doctor.Correlation{
			Signals:     []string{"tcp", "syscall"},
			Description: "TCP issues (retransmits/high RTT) are likely causing network-related syscall latency spikes.",
			Confidence:  0.80,
		})
	}

	// Scheduler + disk → I/O wait causing CPU contention.
	if signals["sched"] && signals["diskio"] {
		correlations = append(correlations, doctor.Correlation{
			Signals:     []string{"sched", "diskio"},
			Description: "CPU scheduler contention may be exacerbated by I/O wait — processes blocked on disk are consuming run queue slots.",
			Confidence:  0.75,
		})
	}

	// FD leak + OOM → resource exhaustion cascade.
	if signals["fd"] && signals["oom"] {
		correlations = append(correlations, doctor.Correlation{
			Signals:     []string{"fd", "oom"},
			Description: "FD leak and OOM events suggest a resource exhaustion cascade — a process may be leaking both file descriptors and memory.",
			Confidence:  0.90,
		})
	}

	return correlations
}
