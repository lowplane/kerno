// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Renderer writes a diagnostic report to an output stream.
type Renderer interface {
	Render(w io.Writer, report *Report) error
}

// ── Pretty Renderer (colored terminal output) ───────────────────────────────

// PrettyRenderer outputs a human-readable terminal report matching the
// kerno doctor mockup in idea.md.
type PrettyRenderer struct {
	NoColor bool
}

func (r *PrettyRenderer) Render(w io.Writer, report *Report) error {
	// Header.
	fmt.Fprintln(w, "╔═══════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w, "║                     KERNO DOCTOR                        ║")
	fmt.Fprintln(w, "║          Kernel Diagnostic Report                        ║")
	fmt.Fprintln(w, "╚═══════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w)

	// Host info.
	if report.Hostname != "" {
		fmt.Fprintf(w, "Host:     %s\n", report.Hostname)
	}
	if report.KernelVer != "" {
		fmt.Fprintf(w, "Kernel:   %s\n", report.KernelVer)
	}
	if !report.StartTime.IsZero() {
		fmt.Fprintf(w, "Analyzed: %s → %s\n",
			report.StartTime.Format(time.RFC3339),
			report.EndTime.Format("15:04:05 MST"))
	}
	fmt.Fprintln(w)

	// Findings header.
	crit, warn, info := report.CountBySeverity()
	fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
	fmt.Fprintf(w, " FINDINGS  (%d critical · %d warning · %d info)\n", crit, warn, info)
	fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(w)

	// Render each finding.
	for i := range report.Findings {
		r.renderFinding(w, &report.Findings[i])
	}

	// AI analysis section (if available).
	if analysis, ok := report.Analysis.(*AnalysisResponse); ok && analysis != nil {
		r.renderAIAnalysis(w, analysis)
	}

	// Recommended action order (for actionable findings).
	actionFindings := filterActionable(report.Findings)
	if len(actionFindings) > 0 {
		fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
		fmt.Fprintln(w, " RECOMMENDED ACTION ORDER")
		fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
		fmt.Fprintln(w)
		for i, f := range actionFindings {
			urgency := "[MONITOR]"
			if f.Severity == SeverityCritical {
				if f.ETA != nil && *f.ETA < 5*time.Minute {
					urgency = "[NOW]    "
				} else {
					urgency = "[NOW]    "
				}
			} else if f.Severity == SeverityWarning {
				urgency = "[5 MIN]  "
			}
			fmt.Fprintf(w, "  %d. %s %s\n", i+1, urgency, f.Title)
		}
		fmt.Fprintln(w)
	}

	// System summary.
	fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(w, " SYSTEM SUMMARY")
	fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Kernel signals collected:  %d\n", report.EventsCollected)
	fmt.Fprintf(w, "  Analysis duration:         %s\n", report.Duration)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Run `kerno doctor --continuous` to watch for new issues")
	fmt.Fprintln(w, "  Run `kerno doctor --output json` to pipe findings to scripts")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "═══════════════════════════════════════════════════════════")

	return nil
}

func (r *PrettyRenderer) renderFinding(w io.Writer, f *Finding) {
	icon := severityIcon(f.Severity)
	fmt.Fprintf(w, " %s  %s  %s\n", icon, f.Severity, f.Title)
	fmt.Fprintf(w, "     %s\n", strings.Repeat("─", len(f.Title)+2))

	if f.Cause != "" {
		fmt.Fprintf(w, "     Signal:   %s\n", f.Evidence)
	}
	if f.Cause != "" {
		fmt.Fprintf(w, "     Cause:    %s\n", f.Cause)
	}
	if f.Impact != "" {
		fmt.Fprintf(w, "     Impact:   %s\n", f.Impact)
	}
	if len(f.Fix) > 0 {
		fmt.Fprintf(w, "     Fix:      → %s\n", f.Fix[0])
		for _, fix := range f.Fix[1:] {
			fmt.Fprintf(w, "               → %s\n", fix)
		}
	}
	fmt.Fprintln(w)
}

func (r *PrettyRenderer) renderAIAnalysis(w io.Writer, analysis *AnalysisResponse) {
	fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(w, " AI ANALYSIS")
	fmt.Fprintln(w, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(w)

	if analysis.Summary != "" {
		fmt.Fprintf(w, "  %s\n", analysis.Summary)
		fmt.Fprintln(w)
	}

	if len(analysis.Correlations) > 0 {
		fmt.Fprintln(w, "  Cross-Signal Correlations:")
		for _, c := range analysis.Correlations {
			fmt.Fprintf(w, "    • [%s] %s (confidence: %.0f%%)\n",
				strings.Join(c.Signals, " + "), c.Description, c.Confidence*100)
		}
		fmt.Fprintln(w)
	}

	if len(analysis.RootCauses) > 0 {
		fmt.Fprintln(w, "  Root Causes:")
		for i, rc := range analysis.RootCauses {
			fmt.Fprintf(w, "    %d. %s\n", i+1, rc.Description)
			if rc.Fix != "" {
				fmt.Fprintf(w, "       Fix: %s\n", rc.Fix)
			}
		}
		fmt.Fprintln(w)
	}
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "!!"
	case SeverityWarning:
		return "! "
	case SeverityInfo:
		return "  "
	default:
		return "??"
	}
}

func filterActionable(findings []Finding) []Finding {
	var result []Finding
	for i := range findings {
		if findings[i].Severity >= SeverityWarning {
			result = append(result, findings[i])
		}
	}
	return result
}

// ── JSON Renderer ───────────────────────────────────────────────────────────

// JSONRenderer outputs a machine-readable JSON report.
type JSONRenderer struct {
	Pretty bool
}

// jsonReport is the JSON-serializable report structure.
type jsonReport struct {
	Hostname        string          `json:"hostname"`
	KernelVer       string          `json:"kernelVersion"`
	Arch            string          `json:"arch"`
	StartTime       time.Time       `json:"startTime"`
	EndTime         time.Time       `json:"endTime"`
	Duration        string          `json:"duration"`
	Findings        []jsonFinding   `json:"findings"`
	Summary         reportSummary   `json:"summary"`
	Analysis        *AnalysisResponse `json:"analysis,omitempty"`
}

type jsonFinding struct {
	Severity  string   `json:"severity"`
	Rule      string   `json:"rule"`
	Title     string   `json:"title"`
	Signal    string   `json:"signal"`
	Cause     string   `json:"cause"`
	Impact    string   `json:"impact"`
	Evidence  string   `json:"evidence"`
	Fix       []string `json:"fix"`
	ETA       string   `json:"eta,omitempty"`
	Metric    string   `json:"metric,omitempty"`
	Value     float64  `json:"value,omitempty"`
	Threshold float64  `json:"threshold,omitempty"`
	Process   string   `json:"process,omitempty"`
}

type reportSummary struct {
	Critical        int    `json:"critical"`
	Warning         int    `json:"warning"`
	Info            int    `json:"info"`
	EventsCollected uint64 `json:"eventsCollected"`
}

func (r *JSONRenderer) Render(w io.Writer, report *Report) error {
	crit, warn, info := report.CountBySeverity()

	jr := jsonReport{
		Hostname:  report.Hostname,
		KernelVer: report.KernelVer,
		Arch:      report.Arch,
		StartTime: report.StartTime,
		EndTime:   report.EndTime,
		Duration:  report.Duration.String(),
		Summary: reportSummary{
			Critical:        crit,
			Warning:         warn,
			Info:            info,
			EventsCollected: report.EventsCollected,
		},
	}

	if analysis, ok := report.Analysis.(*AnalysisResponse); ok {
		jr.Analysis = analysis
	}

	for _, f := range report.Findings {
		jf := jsonFinding{
			Severity:  f.Severity.String(),
			Rule:      f.Rule,
			Title:     f.Title,
			Signal:    f.Signal,
			Cause:     f.Cause,
			Impact:    f.Impact,
			Evidence:  f.Evidence,
			Fix:       f.Fix,
			Metric:    f.Metric,
			Value:     f.Value,
			Threshold: f.Threshold,
			Process:   f.Process,
		}
		if f.ETA != nil {
			jf.ETA = f.ETAString()
		}
		jr.Findings = append(jr.Findings, jf)
	}

	enc := json.NewEncoder(w)
	if r.Pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(jr)
}
