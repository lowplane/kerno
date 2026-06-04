// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/doctor"
)

func emptySignals() *collector.Signals {
	return &collector.Signals{
		Timestamp: time.Now(),
		Duration:  30 * time.Second,
	}
}

func newSilentAILogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// scriptedProvider returns canned responses, useful for analyzer tests
// that don't need a full HTTP round-trip.
type scriptedProvider struct {
	text   string
	tokens int
	model  string
	err    error
	calls  atomic.Uint64
}

func (p *scriptedProvider) Name() string { return "scripted" }

func (p *scriptedProvider) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	p.calls.Add(1)
	if p.err != nil {
		return nil, p.err
	}
	return &CompletionResponse{Text: p.text, TokensUsed: p.tokens, Model: p.model}, nil
}

// ─── DefaultAnalyzer ───────────────────────────────────────────────────────

func TestAnalyzerHappyPath(t *testing.T) {
	jsonResp := `{
        "summary": "disk slow",
        "rootCauses": [{"description": "fsync stall", "fix": "check ssd", "confidence": 0.9}]
    }`
	prov := &scriptedProvider{text: jsonResp, tokens: 42, model: "test"}

	a := NewAnalyzer(AnalyzerConfig{Provider: prov, Logger: newSilentAILogger()})
	resp, err := a.Analyze(context.Background(), doctor.AnalysisRequest{
		Signals:  emptySignals(),
		Findings: []doctor.Finding{{Rule: "disk_io_bottleneck", Severity: doctor.SeverityCritical}},
	})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if resp.Summary != "disk slow" {
		t.Errorf("Summary = %q", resp.Summary)
	}
	if resp.TokensUsed != 42 {
		t.Errorf("TokensUsed = %d, want 42", resp.TokensUsed)
	}
	if len(resp.RootCauses) != 1 || resp.RootCauses[0].Fix != "check ssd" {
		t.Errorf("RootCauses = %+v", resp.RootCauses)
	}
}

func TestAnalyzerMarkdownFencedJSON(t *testing.T) {
	prov := &scriptedProvider{text: "Here you go:\n```json\n{\"summary\":\"ok\"}\n```\n"}

	a := NewAnalyzer(AnalyzerConfig{Provider: prov, Logger: newSilentAILogger()})
	resp, err := a.Analyze(context.Background(), doctor.AnalysisRequest{Signals: emptySignals()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Summary, "ok") {
		t.Errorf("Summary = %q (markdown fence not stripped)", resp.Summary)
	}
}

func TestAnalyzerFallsBackToPlainTextOnInvalidJSON(t *testing.T) {
	prov := &scriptedProvider{text: "I am not JSON, but I still have something to say."}

	a := NewAnalyzer(AnalyzerConfig{Provider: prov, Logger: newSilentAILogger()})
	resp, err := a.Analyze(context.Background(), doctor.AnalysisRequest{Signals: emptySignals()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Summary, "not JSON") {
		t.Errorf("Summary = %q, want fallback to raw text", resp.Summary)
	}
}

func TestAnalyzerProviderError(t *testing.T) {
	prov := &scriptedProvider{err: errors.New("boom")}

	a := NewAnalyzer(AnalyzerConfig{Provider: prov, Logger: newSilentAILogger()})
	_, err := a.Analyze(context.Background(), doctor.AnalysisRequest{Signals: emptySignals()})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should wrap underlying: %v", err)
	}
	if !strings.Contains(err.Error(), "scripted") {
		t.Errorf("error should mention provider name: %v", err)
	}
}

func TestAnalyzerCacheHit(t *testing.T) {
	prov := &scriptedProvider{text: `{"summary":"first"}`}
	cache := NewCache(time.Hour)

	a := NewAnalyzer(AnalyzerConfig{Provider: prov, Cache: cache, Logger: newSilentAILogger()})

	finding := doctor.Finding{Rule: "x", Severity: doctor.SeverityCritical}

	// First call: miss → provider hit.
	resp1, err := a.Analyze(context.Background(), doctor.AnalysisRequest{Signals: emptySignals(), Findings: []doctor.Finding{finding}})
	if err != nil {
		t.Fatal(err)
	}

	// Second call with identical finding fingerprint: cache hit, no provider call.
	resp2, err := a.Analyze(context.Background(), doctor.AnalysisRequest{Signals: emptySignals(), Findings: []doctor.Finding{finding}})
	if err != nil {
		t.Fatal(err)
	}

	if prov.calls.Load() != 1 {
		t.Errorf("provider called %d times, want 1 (cache should suppress 2nd)", prov.calls.Load())
	}
	if resp1.Summary != resp2.Summary {
		t.Errorf("cached response differs: %q vs %q", resp1.Summary, resp2.Summary)
	}
}

func TestFindingsFingerprintHealthy(t *testing.T) {
	if got := findingsFingerprint(nil); got != "healthy" {
		t.Errorf("nil findings fingerprint = %q, want healthy", got)
	}
}

func TestFindingsFingerprintShape(t *testing.T) {
	findings := []doctor.Finding{
		{Rule: "a", Severity: doctor.SeverityCritical},
		{Rule: "b", Severity: doctor.SeverityWarning},
	}
	fp := findingsFingerprint(findings)
	if !strings.Contains(fp, "a:") || !strings.Contains(fp, "b:") {
		t.Errorf("fingerprint %q should embed rule names", fp)
	}
	if !strings.Contains(fp, "|") {
		t.Errorf("fingerprint should join with '|', got %q", fp)
	}
}

func TestExtractJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "json fenced block",
			in:   "```json\n{\"a\":1}\n```",
			want: "\n{\"a\":1}\n",
		},
		{
			name: "json fenced block with surrounding text",
			in:   "prelude ```json\n{\"x\":2}\n``` postlude",
			want: "\n{\"x\":2}\n",
		},
		{
			name: "generic fenced block",
			in:   "```\n{\"y\":3}\n```",
			want: "\n{\"y\":3}\n",
		},
		{
			name: "raw json",
			in:   "{\"raw\":true}",
			want: "{\"raw\":true}",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
		{
			name: "bare fence",
			in:   "```",
			want: "```",
		},
		{
			name: "malformed json",
			in:   "{bad json",
			want: "{bad json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := extractJSON(tc.in)

			if got != tc.want {
				t.Fatalf("extractJSON(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
func TestFallbackAnalyzerEmptyFindings(t *testing.T) {
	f := NewFallbackAnalyzer()

	resp, err := f.Analyze(context.Background(), doctor.AnalysisRequest{
		Signals: emptySignals(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(resp.Summary, "normal thresholds") {
		t.Errorf("Summary = %q, want healthy phrase", resp.Summary)
	}
}
func TestFallbackAnalyzerCountsBySeverity(t *testing.T) {
	f := NewFallbackAnalyzer()

	findings := []doctor.Finding{
		{Severity: doctor.SeverityCritical, Title: "disk slow", Cause: "fsync stalls", Rule: "disk", Fix: []string{"upgrade ssd"}, Signal: "diskio"},
		{Severity: doctor.SeverityCritical, Title: "another", Cause: "x", Rule: "y", Signal: "syscall"},
		{Severity: doctor.SeverityWarning, Title: "warn", Cause: "z", Rule: "w", Signal: "tcp"},
		{Severity: doctor.SeverityInfo, Title: "info", Cause: "i", Rule: "i", Signal: "fd"},
	}

	resp, err := f.Analyze(context.Background(), doctor.AnalysisRequest{
		Findings: findings,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(resp.Summary, "2 critical") {
		t.Errorf("Summary should mention 2 critical: %q", resp.Summary)
	}
	if !strings.Contains(resp.Summary, "1 warning") {
		t.Errorf("Summary should mention 1 warning: %q", resp.Summary)
	}
	if !strings.Contains(resp.Summary, "disk slow") {
		t.Errorf("Summary should highlight first finding: %q", resp.Summary)
	}

	if len(resp.RootCauses) != 3 {
		t.Errorf("RootCauses = %d, want 3 (excludes info)", len(resp.RootCauses))
	}

	if resp.RootCauses[0].Fix != "upgrade ssd" {
		t.Errorf("first RootCause Fix = %q", resp.RootCauses[0].Fix)
	}
}
func TestDetectSimpleCorrelations(t *testing.T) {
	cases := []struct {
		name    string
		signals []string
		want    int
	}{
		{"diskio+syscall", []string{"diskio", "syscall"}, 1},
		{"tcp+syscall", []string{"tcp", "syscall"}, 1},
		{"sched+diskio", []string{"sched", "diskio"}, 1},
		{"fd+oom", []string{"fd", "oom"}, 1},
		{"all four pairs", []string{"diskio", "syscall", "tcp", "sched", "fd", "oom"}, 4},
		{"unrelated", []string{"foo", "bar"}, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := make([]doctor.Finding, len(c.signals))
			for i, sig := range c.signals {
				findings[i] = doctor.Finding{Signal: sig}
			}

			cors := detectSimpleCorrelations(findings)

			if len(cors) != c.want {
				t.Errorf("got %d correlations, want %d", len(cors), c.want)
			}
		})
	}
}
