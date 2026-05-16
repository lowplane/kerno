// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// BaselinesConfig controls the adaptive baseline engine.
type BaselinesConfig struct {
	Enabled       bool
	Warmup        time.Duration // no findings until this much data is seen
	Sensitivity   float64       // std-devs (sigma mode) or ratio multiplier
	HistoryWindow time.Duration // ring-buffer width
}

// DetectionMode selects the anomaly-detection algorithm for a rule.
type DetectionMode int

const (
	// SigmaMode fires when (value - mean) / stddev > Sensitivity.
	// Best for roughly-normal metrics: scheduler delay, TCP RTT.
	SigmaMode DetectionMode = iota

	// RatioMode fires when value / mean > Sensitivity.
	// Best for log-distributed / skewed metrics: fsync P99, write latency.
	RatioMode
)

// CheckResult is returned by Tracker.Check.
type CheckResult struct {
	Exceeded bool
	// Annotation is a human-readable summary suitable for Finding.BaselineAnnotation.
	Annotation string
	// SuggestedSeverity is WARNING for a 3x/3Ïƒ breach, CRITICAL for 10x/10Ïƒ.
	SuggestedSeverity Severity
}

// SeverityForRatio maps a ratio (value/baseline) to a suggested severity.
// 3â€“10Ã— â†’ WARNING; >10Ã— â†’ CRITICAL.
func SeverityForRatio(ratio float64) Severity {
	if ratio >= 10 {
		return SeverityCritical
	}
	return SeverityWarning
}

// Tracker maintains per-(rule, key) sliding-window baselines.
// It is safe for concurrent use.
type Tracker struct {
	cfg  BaselinesConfig
	mu   sync.Mutex
	seqs map[string]*ringSeq
}

// NewTracker creates a Tracker with the given config.
// When cfg.Enabled is false every call is a no-op.
func NewTracker(cfg BaselinesConfig) *Tracker {
	return &Tracker{
		cfg:  cfg,
		seqs: make(map[string]*ringSeq),
	}
}

// Observe records one sample.  key = rule + ":" + pod/comm identifier.
func (t *Tracker) Observe(key string, valueNs float64, at time.Time) {
	if !t.cfg.Enabled {
		return
	}
	t.mu.Lock()
	seq := t.seqs[key]
	if seq == nil {
		seq = newRingSeq(t.cfg.HistoryWindow)
		t.seqs[key] = seq
	}
	t.mu.Unlock()
	seq.add(valueNs, at)
}

// Check evaluates whether value is anomalous relative to the baseline.
// Returns (false, zero) during warm-up or when insufficient data exists.
func (t *Tracker) Check(key string, valueNs float64, mode DetectionMode, at time.Time) CheckResult {
	if !t.cfg.Enabled {
		return CheckResult{}
	}
	t.mu.Lock()
	seq := t.seqs[key]
	t.mu.Unlock()
	if seq == nil {
		return CheckResult{}
	}
	mean, stddev, count, oldest := seq.stats(at)
	if count < 2 {
		return CheckResult{}
	}
	// Still in warm-up window.
	if at.Sub(oldest) < t.cfg.Warmup {
		return CheckResult{}
	}

	switch mode {
	case RatioMode:
		if mean <= 0 {
			return CheckResult{}
		}
		ratio := valueNs / mean
		if ratio <= t.cfg.Sensitivity {
			return CheckResult{}
		}
		sev := SeverityForRatio(ratio)
		return CheckResult{
			Exceeded:          true,
			SuggestedSeverity: sev,
			Annotation: fmt.Sprintf("%.1fÃ— the %.0f-min baseline of %s",
				ratio, t.cfg.HistoryWindow.Minutes(), fmtNsDuration(mean)),
		}

	default: // SigmaMode
		if stddev <= 0 {
			return CheckResult{}
		}
		sigma := (valueNs - mean) / stddev
		if sigma <= t.cfg.Sensitivity {
			return CheckResult{}
		}
		sev := SeverityForRatio(sigma / t.cfg.Sensitivity) // reuse ratio helper
		return CheckResult{
			Exceeded:          true,
			SuggestedSeverity: sev,
			Annotation: fmt.Sprintf("%.1fÏƒ above %.0f-min baseline of %s (Ïƒ=%s)",
				sigma, t.cfg.HistoryWindow.Minutes(),
				fmtNsDuration(mean), fmtNsDuration(stddev)),
		}
	}
}

// â”€â”€ ring buffer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

type sample struct {
	v  float64
	at time.Time
}

type ringSeq struct {
	window  time.Duration
	mu      sync.Mutex
	samples []sample
	head    int
	full    bool
}

const ringCap = 256

func newRingSeq(window time.Duration) *ringSeq {
	return &ringSeq{
		window:  window,
		samples: make([]sample, ringCap),
	}
}

func (r *ringSeq) add(v float64, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples[r.head] = sample{v, at}
	r.head = (r.head + 1) % ringCap
	if r.head == 0 {
		r.full = true
	}
}

// stats returns (mean, stddev, count, oldestTimestamp) for samples within window.
func (r *ringSeq) stats(now time.Time) (mean, stddev float64, count int, oldest time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := now.Add(-r.window)
	var sum, sum2 float64
	oldest = now

	visit := func(s sample) {
		if s.at.IsZero() || s.at.Before(cutoff) {
			return
		}
		count++
		sum += s.v
		sum2 += s.v * s.v
		if s.at.Before(oldest) {
			oldest = s.at
		}
	}

	n := ringCap
	if !r.full {
		n = r.head
	}
	for i := 0; i < n; i++ {
		visit(r.samples[i])
	}
	if count == 0 {
		return
	}
	mean = sum / float64(count)
	variance := sum2/float64(count) - mean*mean
	if variance < 0 {
		variance = 0
	}
	stddev = math.Sqrt(variance)
	// Stddev floor: 1% of mean prevents false-positives on perfectly flat signals.
	if stddev < mean*0.01 {
		stddev = mean * 0.01
	}
	return
}

// fmtNsDuration formats a nanosecond float64 as a human-readable duration.
func fmtNsDuration(ns float64) string {
	switch {
	case ns >= 1e9:
		return fmt.Sprintf("%.2fs", ns/1e9)
	case ns >= 1e6:
		return fmt.Sprintf("%.1fms", ns/1e6)
	case ns >= 1e3:
		return fmt.Sprintf("%.0fÂµs", ns/1e3)
	default:
		return fmt.Sprintf("%.0fns", ns)
	}
}


// EvaluateWithBaselines satisfies the call in engine.go (line 113).
// It delegates to Check so all baseline logic stays in one place.
func (t *BaselineTracker) EvaluateWithBaselines(
rule, key string,
now time.Time,
value float64,
logDistributed bool,
) BaselineResult {
return t.Check(rule, key, now, value, logDistributed)
}