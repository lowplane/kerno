// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/optiqor/kerno/internal/audit"
	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
)

// Analyzer is the optional AI analysis interface.
type Analyzer interface {
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error)
}

// AnalysisRequest contains the data sent to the AI analyzer.
type AnalysisRequest struct {
	Signals  *collector.Signals
	Findings []Finding
	History  []*collector.Signals
}

// AnalysisResponse contains AI-generated insights.
type AnalysisResponse struct {
	Summary      string        `json:"summary"`
	Correlations []Correlation `json:"correlations,omitempty"`
	RootCauses   []RootCause   `json:"rootCauses,omitempty"`
	Anomalies    []Anomaly     `json:"anomalies,omitempty"`
	TrendSummary string        `json:"trendSummary,omitempty"`
	TokensUsed   int           `json:"tokensUsed"`
}

// Correlation describes a cross-signal pattern.
type Correlation struct {
	Signals     []string `json:"signals"`
	Description string   `json:"description"`
	Confidence  float64  `json:"confidence"`
}

// RootCause is a prioritized explanation with a fix suggestion.
type RootCause struct {
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Fix         string   `json:"fix"`
	Confidence  float64  `json:"confidence"`
}

// Anomaly describes a deviation from baseline behavior.
type Anomaly struct {
	Signal      string `json:"signal"`
	Metric      string `json:"metric"`
	CurrentVal  string `json:"currentVal"`
	BaselineVal string `json:"baselineVal"`
	Description string `json:"description"`
}

// Engine orchestrates the full doctor diagnostic pipeline:
//
//	collect signals → evaluate rules → (optional AI enrichment) → render report
type Engine struct {
	// thresholds are set at construction time and are read-only after that.
	// Changing thresholds requires a daemon restart (restart-required config class).
	thresholds config.DoctorThresholds

	analyzer   Analyzer
	logger     *slog.Logger
	auditLog   *audit.Logger
	history    []*collector.Signals
	maxHistory int
}

// NewEngine creates a new diagnostic engine.
// Pass nil for analyzer to run without AI enrichment.
// Pass audit.Noop() for auditLog to disable audit emission.
func NewEngine(thresholds config.DoctorThresholds, analyzer Analyzer, auditLog *audit.Logger, logger *slog.Logger) *Engine {
	if auditLog == nil {
		auditLog = audit.Noop()
	}
	return &Engine{
		thresholds: thresholds,
		analyzer:   analyzer,
		logger:     logger,
		auditLog:   auditLog,
		maxHistory: 10,
	}
}

// Diagnose runs the full diagnostic pipeline against the supplied signals.
func (e *Engine) Diagnose(ctx context.Context, signals *collector.Signals) (*Report, error) {
	start := time.Now()

	// Phase 1: Deterministic rule evaluation.
	findings := Evaluate(signals, e.thresholds)
	e.logger.Debug("rules evaluated",
		"findings", len(findings),
		"duration_ms", time.Since(start).Milliseconds(),
	)

	// Phase 2: Optional AI enrichment (non-fatal on failure).
	var analysis *AnalysisResponse
	if e.analyzer != nil && hasActionableFindings(findings) {
		e.logger.Info("running AI analysis")
		var err error
		analysis, err = e.analyzer.Analyze(ctx, AnalysisRequest{
			Signals:  signals,
			Findings: findings,
			History:  e.history,
		})
		if err != nil {
			e.logger.Warn("AI analysis failed, continuing with rule-based results", "error", err)
		}
	}

	// Phase 3: Build the report.
	hostname, _ := os.Hostname()

	// cycleID links this Diagnose run to all its audit records.
	cycleID := fmt.Sprintf("cycle-%s", signals.Timestamp.UTC().Format("20060102-150405"))

	report := &Report{
		Hostname:  hostname,
		KernelVer: signals.Host.KernelVer,
		Arch:      runtime.GOARCH,
		StartTime: signals.Timestamp.Add(-signals.Duration),
		EndTime:   signals.Timestamp,
		Duration:  signals.Duration,
		Findings:  findings,
		Analysis:  analysis,
		// Raw signals are carried through for the JSON renderer; the
		// pretty renderer ignores this field.
		Signals: signals,
	}

	// Track event counts for the report summary.
	if signals.Syscall != nil {
		report.EventsCollected += signals.Syscall.TotalCount
	}
	if signals.Sched != nil {
		report.EventsCollected += signals.Sched.TotalCount
	}

	// Phase 4: Emit finding.emit audit records for every WARNING/CRITICAL finding.
	// INFO findings skipped — too noisy for compliance log.
	for i := range findings {
		f := &findings[i]
		if f.Severity < SeverityWarning {
			continue
		}
		e.auditLog.RecordFindingEmit(
			f.Rule,
			f.Severity.String(),
			"log",
			hashFinding(f),
			cycleID,
		)
	}

	// Phase 5: Append to history ring buffer.
	e.appendHistory(signals)

	return report, nil
}

// EmitFinding audit-logs a single finding being dispatched to a named sink
// (e.g. "slack", "pagerduty"). Call this from the sink dispatcher after
// Diagnose() so the audit record carries the real sink name.
func (e *Engine) EmitFinding(f *Finding, sink, cycleID string) {
	e.auditLog.RecordFindingEmit(
		f.Rule,
		f.Severity.String(),
		sink,
		hashFinding(f),
		cycleID,
	)
}

func (e *Engine) appendHistory(signals *collector.Signals) {
	e.history = append(e.history, signals)
	if len(e.history) > e.maxHistory {
		e.history = e.history[1:]
	}
}

// hashFinding returns a 16-char FNV-1a fingerprint of the finding's
// non-PII fields for payload traceability.
func hashFinding(f *Finding) string {
	payload, err := json.Marshal(struct {
		Rule     string `json:"rule"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
	}{
		Rule:     f.Rule,
		Severity: f.Severity.String(),
		Title:    f.Title,
	})
	if err != nil {
		return "hash-error"
	}
	return audit.HashPayload(string(payload))
}

// hasActionableFindings returns true if there is at least one WARNING or
// CRITICAL finding — the threshold below which AI enrichment is not worthwhile.
func hasActionableFindings(findings []Finding) bool {
	for i := range findings {
		if findings[i].Severity >= SeverityWarning {
			return true
		}
	}
	return false
}

// FilterCriticalFindings returns only critical severity findings from the list
func FilterCriticalFindings(findings []Finding) []Finding {
	filtered := make([]Finding, 0, len(findings))
	for i := range findings {
		if findings[i].Severity == SeverityCritical {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}
