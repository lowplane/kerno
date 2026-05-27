// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// Renderer writes a diagnostic report to an output stream.
type Renderer interface {
	Render(w io.Writer, report *Report) error
}

// ── Pretty Renderer (production-grade terminal output) ──────────────────────

// PrettyRenderer outputs a human-readable incident report with ANSI colors,
// box-drawn finding cards, and bar-chart signal visualizations.
type PrettyRenderer struct {
	NoColor  bool
	NoBanner bool
}

const (
	prBoxWidth    = 74
	prLogoGap     = 48
	prLabelColumn = 10
	prBarWidth    = 32
	prThreshBar   = 13
)

var prKernoLogo = []string{
	" ██╗  ██╗███████╗██████╗ ███╗   ██╗ ██████╗",
	" ██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔═══██╗",
	" █████╔╝ █████╗  ██████╔╝██╔██╗ ██║██║   ██║",
	" ██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║",
	" ██║  ██╗███████╗██║  ██║██║ ╚████║╚██████╔╝",
	" ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝",
}

type palette struct {
	reset, bold, dim                              string
	red, yellow, green, cyan, magenta, blue, gray string
}

func newPalette(noColor bool) palette {
	if noColor {
		return palette{}
	}
	return palette{
		reset:   "\x1b[0m",
		bold:    "\x1b[1m",
		dim:     "\x1b[2m",
		red:     "\x1b[38;5;203m",
		yellow:  "\x1b[38;5;214m",
		green:   "\x1b[38;5;114m",
		cyan:    "\x1b[38;5;117m",
		magenta: "\x1b[38;5;177m",
		blue:    "\x1b[38;5;75m",
		gray:    "\x1b[38;5;244m",
	}
}

func (r *PrettyRenderer) Render(w io.Writer, report *Report) error {
	p := newPalette(r.NoColor)

	if !r.NoBanner {
		r.renderHeader(w, report, p)
	}

	r.renderDegradation(w, report, p)
	r.renderTriage(w, report, p)
	for i := range report.Findings {
		r.renderFinding(w, &report.Findings[i], p)
	}
	if analysis, ok := report.Analysis.(*AnalysisResponse); ok && analysis != nil {
		r.renderAIAnalysis(w, analysis, p)
	}
	r.renderRecommendedOrder(w, report, p)
	r.renderSummary(w, report, p)
	return nil
}

// renderDegradation surfaces eBPF-load failures as a single visible
// panel directly under the header. Without this they show up only as
// scattered WARN log lines on stderr — a poor signal for "your report
// is missing data and here is exactly how to fix it".
func (r *PrettyRenderer) renderDegradation(w io.Writer, report *Report, p palette) {
	if len(report.LoadFailures) == 0 {
		return
	}

	// Pick the most actionable hint to headline. If multiple failures
	// share a hint (typical: "re-run with sudo" for all), use that;
	// otherwise list each program with its individual hint.
	hintCounts := map[string]int{}
	for _, f := range report.LoadFailures {
		if f.Hint != "" {
			hintCounts[f.Hint]++
		}
	}
	var topHint string
	topCount := 0
	for h, c := range hintCounts {
		if c > topCount {
			topHint = h
			topCount = c
		}
	}

	progs := make([]string, len(report.LoadFailures))
	for i, f := range report.LoadFailures {
		progs[i] = f.Program
	}

	fmt.Fprintf(w, "\n %s%s%s ─────────────────────────────────────── %sdegraded%s\n",
		p.yellow, "▲ EBPF DEGRADATION", p.reset, p.dim, p.reset)
	fmt.Fprintf(w, "   %s%d/%d eBPF programs failed to load%s: %s\n",
		p.bold, len(report.LoadFailures), len(report.LoadFailures)+report.ProgramsLoaded, p.reset,
		strings.Join(progs, ", "))
	if topHint != "" {
		fmt.Fprintf(w, "   %sFix:%s %s%s%s\n", p.dim, p.reset, p.yellow, topHint, p.reset)
	}
	fmt.Fprintln(w)
}

// ── Header ──────────────────────────────────────────────────────────────────

func (r *PrettyRenderer) renderHeader(w io.Writer, report *Report, p palette) {
	title := "KERNO DOCTOR"
	subtitle := "Kernel Diagnostic Report"

	meta := []string{
		p.bold + title + p.reset,
		p.dim + strings.Repeat("─", utf8.RuneCountInString(title)) + p.reset,
		p.dim + subtitle + p.reset,
		"",
	}
	if report.Hostname != "" {
		meta = append(meta, metaField(p, "Host", report.Hostname))
	}
	if report.Environment != "" {
		meta = append(meta, metaField(p, "Env", report.Environment))
	}
	kernel := report.KernelVer
	if kernel != "" && report.Arch != "" {
		kernel += " · " + report.Arch
	}
	if kernel != "" {
		meta = append(meta, metaField(p, "Kernel", kernel))
	}
	windowText := formatDuration(report.Duration)
	if report.EventsCollected > 0 {
		if windowText != "" {
			windowText += " · "
		}
		windowText += formatUint(report.EventsCollected) + " events"
	}
	if windowText != "" {
		meta = append(meta, metaField(p, "Window", windowText))
	}
	if report.ProgramsLoaded > 0 || len(report.LoadFailures) > 0 {
		total := report.ProgramsLoaded + len(report.LoadFailures)
		programs := fmt.Sprintf("%d/%d eBPF loaded", report.ProgramsLoaded, total)
		meta = append(meta, metaField(p, "Probes", programs))
	}

	maxRows := len(prKernoLogo)
	if len(meta) > maxRows {
		maxRows = len(meta)
	}
	for i := 0; i < maxRows; i++ {
		var l, m string
		if i < len(prKernoLogo) {
			l = prKernoLogo[i]
		}
		if i < len(meta) {
			m = meta[i]
		}
		pad := prLogoGap - utf8.RuneCountInString(l)
		if pad < 2 {
			pad = 2
		}
		fmt.Fprintf(w, "%s%s%s%s%s\n", p.cyan+p.bold, l, p.reset, strings.Repeat(" ", pad), m)
	}
	fmt.Fprintln(w)
}

func metaField(p palette, label, value string) string {
	return fmt.Sprintf("%s%-7s%s  %s", p.gray, label, p.reset, value)
}

// ── Triage banner ───────────────────────────────────────────────────────────

func (r *PrettyRenderer) renderTriage(w io.Writer, report *Report, p palette) {
	crit, warn, info := report.CountBySeverity()
	duration := formatDuration(report.Duration)

	label := " FINDINGS "
	rule := strings.Repeat("─", prBoxWidth-utf8.RuneCountInString(label)-utf8.RuneCountInString(duration)-2)
	if rule == "" {
		rule = strings.Repeat("─", 4)
	}
	fmt.Fprintf(w, "%s%s%s%s%s %s%s%s\n",
		p.bold, label, p.reset,
		p.gray, rule,
		p.gray, duration, p.reset)

	dots := severityDots(p, crit, warn, info)
	counts := fmt.Sprintf("%d critical · %d warning · %d info", crit, warn, info)
	fmt.Fprintf(w, "   %s   %s%s%s\n", dots, p.dim, counts, p.reset)
	fmt.Fprintln(w)
}

func severityDots(p palette, crit, warn, info int) string {
	var b strings.Builder
	for i := 0; i < crit; i++ {
		b.WriteString(p.red + "●" + p.reset + " ")
	}
	for i := 0; i < warn; i++ {
		b.WriteString(p.yellow + "▲" + p.reset + " ")
	}
	for i := 0; i < info; i++ {
		b.WriteString(p.blue + "•" + p.reset + " ")
	}
	if crit+warn+info == 0 {
		b.WriteString(p.green + "✓" + p.reset)
	}
	return strings.TrimRight(b.String(), " ")
}

// ── Finding card ────────────────────────────────────────────────────────────

func (r *PrettyRenderer) renderFinding(w io.Writer, f *Finding, p palette) {
	sevColor, bullet := severityStyle(f.Severity, p)

	// Boxed title.
	top := p.dim + sevColor + "┏" + strings.Repeat("━", prBoxWidth-2) + "┓" + p.reset
	bot := p.dim + sevColor + "┗" + strings.Repeat("━", prBoxWidth-2) + "┛" + p.reset
	fmt.Fprintln(w, top)

	left := fmt.Sprintf(" %s  %s%s%s  ·  %s%s%s",
		bullet,
		sevColor+p.bold, f.Severity.String(), p.reset,
		p.bold, f.Title, p.reset)
	right := ""
	if f.ETA != nil {
		right = fmt.Sprintf("%sETA %s%s", p.yellow, f.ETAString(), p.reset)
	}
	leftVis := visibleLen(left)
	rightVis := visibleLen(right)
	pad := prBoxWidth - 2 - leftVis - rightVis - 1
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(w, "%s┃%s%s%s%s%s%s┃%s\n",
		p.dim+sevColor, p.reset,
		left,
		strings.Repeat(" ", pad),
		right,
		"",
		p.dim+sevColor, p.reset)
	fmt.Fprintln(w, bot)

	// Body.
	if f.Process != "" {
		r.kv(w, p, "Process", f.Process)
	}
	if f.Signal != "" {
		r.kv(w, p, "Signal", p.cyan+f.Signal+p.reset)
	}
	if f.Evidence != "" {
		for i, line := range strings.Split(f.Evidence, "\n") {
			label := "Evidence"
			if i > 0 {
				label = ""
			}
			r.kv(w, p, label, strings.TrimSpace(line))
		}
	}
	if f.Value > 0 && f.Threshold > 0 {
		r.renderBar(w, p, f, sevColor)
	}
	if f.Cause != "" {
		r.kv(w, p, "Cause", f.Cause)
	}
	if f.Impact != "" {
		r.kv(w, p, "Impact", f.Impact)
	}
	if len(f.Fix) > 0 {
		for i, fx := range f.Fix {
			label := ""
			if i == 0 {
				label = "Fix"
			}
			fmt.Fprintf(w, "     %s%-*s%s  %s→%s %s\n",
				p.gray, prLabelColumn, label, p.reset,
				p.green, p.reset, fx)
		}
	}
	fmt.Fprintln(w)
}

func (r *PrettyRenderer) kv(w io.Writer, p palette, label, value string) {
	fmt.Fprintf(w, "     %s%-*s%s  %s\n",
		p.gray, prLabelColumn, label, p.reset, value)
}

func severityStyle(s Severity, p palette) (color, bullet string) {
	switch s {
	case SeverityCritical:
		return p.red, p.red + "●" + p.reset
	case SeverityWarning:
		return p.yellow, p.yellow + "▲" + p.reset
	case SeverityInfo:
		return p.blue, p.blue + "•" + p.reset
	default:
		return p.gray, p.gray + "·" + p.reset
	}
}

// ── Signal bar chart ────────────────────────────────────────────────────────

func (r *PrettyRenderer) renderBar(w io.Writer, p palette, f *Finding, sevColor string) {
	ratio := f.Value / f.Threshold
	if ratio < 0 {
		ratio = 0
	}

	// Threshold anchors at prThreshBar cells; value scales proportionally
	// (capped at prBarWidth). Sub-1-ratio values still show at least one cell
	// so "at limit" is visually distinct from "no data".
	valCells := int(float64(prThreshBar) * ratio)
	if valCells > prBarWidth {
		valCells = prBarWidth
	}
	if valCells < 1 && f.Value > 0 {
		valCells = 1
	}

	valueStr := formatMetricValue(f.Metric, f.Value)
	threshStr := formatMetricValue(f.Metric, f.Threshold)

	valBar := strings.Repeat("▇", valCells) + strings.Repeat("·", prBarWidth-valCells)
	thBar := strings.Repeat("▇", prThreshBar) + strings.Repeat("·", prBarWidth-prThreshBar)

	fmt.Fprintf(w, "     %s%-*s%s  %s%s%s  %s\n",
		p.gray, prLabelColumn, "Value", p.reset,
		sevColor, valBar, p.reset, valueStr)
	fmt.Fprintf(w, "     %s%-*s%s  %s%s%s  %s%s%s\n",
		p.gray, prLabelColumn, "Limit", p.reset,
		p.gray, thBar, p.reset,
		p.dim, threshStr, p.reset)
}

// formatMetricValue formats a raw metric value for human display, guessing
// units from the metric name suffix: *_p99 (ns), *_pct, *_per_sec.
func formatMetricValue(metric string, v float64) string {
	if v == 0 {
		return "—"
	}
	m := strings.ToLower(metric)
	switch {
	case strings.HasSuffix(m, "_p99") || strings.HasSuffix(m, "_p95") || strings.HasSuffix(m, "_p50") ||
		strings.Contains(m, "latency") || strings.Contains(m, "_ns") || strings.Contains(m, "nanoseconds"):
		return formatNanos(v)
	case strings.HasSuffix(m, "_pct") || strings.Contains(m, "percent"):
		return fmt.Sprintf("%.2f %%", v)
	case strings.Contains(m, "per_sec"):
		return fmt.Sprintf("%.1f /s", v)
	case strings.Contains(m, "bytes"):
		return formatBytes(uint64(v))
	default:
		if v >= 100 {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%.2f", v)
	}
}

func formatNanos(ns float64) string {
	switch {
	case ns >= 1e9:
		return fmt.Sprintf("%.2f s", ns/1e9)
	case ns >= 1e6:
		return fmt.Sprintf("%.1f ms", ns/1e6)
	case ns >= 1e3:
		return fmt.Sprintf("%.0f µs", ns/1e3)
	default:
		return fmt.Sprintf("%.0f ns", ns)
	}
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if d >= time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.String()
}

func formatUint(n uint64) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	off := len(s) % 3
	if off > 0 {
		b.WriteString(s[:off])
		if len(s) > off {
			b.WriteByte(',')
		}
	}
	for i := off; i+3 <= len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// ── AI analysis ─────────────────────────────────────────────────────────────

func (r *PrettyRenderer) renderAIAnalysis(w io.Writer, analysis *AnalysisResponse, p palette) {
	label := " AI ANALYSIS "
	rule := strings.Repeat("─", prBoxWidth-utf8.RuneCountInString(label)-2)
	fmt.Fprintf(w, "%s%s%s%s%s%s\n",
		p.bold+p.magenta, label, p.reset,
		p.gray, rule, p.reset)
	fmt.Fprintln(w)

	if analysis.Summary != "" {
		for _, line := range wrapText(analysis.Summary, prBoxWidth-6) {
			fmt.Fprintf(w, "   %s\n", line)
		}
		fmt.Fprintln(w)
	}

	if len(analysis.Correlations) > 0 {
		fmt.Fprintf(w, "   %sCross-Signal Correlations%s\n", p.bold, p.reset)
		for _, c := range analysis.Correlations {
			fmt.Fprintf(w, "     %s•%s %s[%s]%s %s %s(confidence: %.0f%%)%s\n",
				p.cyan, p.reset,
				p.cyan, strings.Join(c.Signals, " + "), p.reset,
				c.Description,
				p.dim, c.Confidence*100, p.reset)
		}
		fmt.Fprintln(w)
	}

	if len(analysis.RootCauses) > 0 {
		fmt.Fprintf(w, "   %sRoot Causes%s\n", p.bold, p.reset)
		for i, rc := range analysis.RootCauses {
			fmt.Fprintf(w, "     %s%d.%s %s\n", p.magenta, i+1, p.reset, rc.Description)
			if rc.Fix != "" {
				fmt.Fprintf(w, "        %s→%s %s\n", p.green, p.reset, rc.Fix)
			}
		}
		fmt.Fprintln(w)
	}
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, word := range words[1:] {
		if utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(word) > width {
			lines = append(lines, cur)
			cur = word
			continue
		}
		cur += " " + word
	}
	lines = append(lines, cur)
	return lines
}

// ── Recommended order ───────────────────────────────────────────────────────

func (r *PrettyRenderer) renderRecommendedOrder(w io.Writer, report *Report, p palette) {
	actionFindings := filterActionable(report.Findings)
	if len(actionFindings) == 0 {
		return
	}
	label := " RECOMMENDED ACTION ORDER "
	rule := strings.Repeat("─", prBoxWidth-utf8.RuneCountInString(label)-2)
	fmt.Fprintf(w, "%s%s%s%s%s%s\n",
		p.bold, label, p.reset,
		p.gray, rule, p.reset)
	fmt.Fprintln(w)

	for i, f := range actionFindings {
		urgency, color := "[MONITOR]", p.blue
		switch f.Severity {
		case SeverityCritical:
			urgency, color = "[NOW]    ", p.red
		case SeverityWarning:
			urgency, color = "[5 MIN]  ", p.yellow
		case SeverityInfo:
		}
		ctx := ""
		if f.Process != "" {
			ctx = fmt.Sprintf("  %s(%s)%s", p.dim, f.Process, p.reset)
		}
		fmt.Fprintf(w, "   %s%d.%s  %s%s%s  %s%s\n",
			p.bold, i+1, p.reset,
			color, urgency, p.reset,
			f.Title, ctx)
	}
	fmt.Fprintln(w)
}

// ── System summary ──────────────────────────────────────────────────────────

func (r *PrettyRenderer) renderSummary(w io.Writer, report *Report, p palette) {
	label := " SYSTEM SUMMARY "
	rule := strings.Repeat("─", prBoxWidth-utf8.RuneCountInString(label)-2)
	fmt.Fprintf(w, "%s%s%s%s%s%s\n",
		p.bold, label, p.reset,
		p.gray, rule, p.reset)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "   %sKernel signals collected%s  %s%d%s\n",
		p.gray, p.reset, p.bold, report.EventsCollected, p.reset)
	fmt.Fprintf(w, "   %sAnalysis duration%s         %s\n",
		p.gray, p.reset, report.Duration)
	if report.ProgramsLoaded > 0 {
		fmt.Fprintf(w, "   %seBPF programs loaded%s      %d\n",
			p.gray, p.reset, report.ProgramsLoaded)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "   %skerno doctor --ai%s             for AI-powered root-cause analysis\n", p.dim, p.reset)
	fmt.Fprintf(w, "   %skerno doctor --output json%s    for runbooks and Slack bots\n", p.dim, p.reset)
	fmt.Fprintf(w, "   %skerno predict%s                 to surface failures before they page you\n", p.dim, p.reset)
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.gray+strings.Repeat("═", prBoxWidth)+p.reset)
}

// ── helpers ─────────────────────────────────────────────────────────────────

func filterActionable(findings []Finding) []Finding {
	result := make([]Finding, 0, len(findings))
	for i := range findings {
		if findings[i].Severity >= SeverityWarning {
			result = append(result, findings[i])
		}
	}
	return result
}

func stripANSI(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		if in {
			if r == 'm' {
				in = false
			}
			continue
		}
		if r == '\x1b' {
			in = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func visibleLen(s string) int {
	return utf8.RuneCountInString(stripANSI(s))
}

// ── JSON Renderer ───────────────────────────────────────────────────────────

// JSONRenderer outputs a machine-readable JSON report.
type JSONRenderer struct {
	Pretty bool
}

// jsonReport is the JSON-serializable report structure.
type jsonReport struct {
	Hostname  string            `json:"hostname"`
	KernelVer string            `json:"kernelVersion"`
	Arch      string            `json:"arch"`
	StartTime time.Time         `json:"startTime"`
	EndTime   time.Time         `json:"endTime"`
	Duration  string            `json:"duration"`
	Findings  []jsonFinding     `json:"findings"`
	Summary   reportSummary     `json:"summary"`
	Analysis  *AnalysisResponse `json:"analysis,omitempty"`
	Signals   any               `json:"signals,omitempty"`
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

	if report.Signals != nil {
		jr.Signals = report.Signals
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
