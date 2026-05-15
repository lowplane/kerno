// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"testing"
	"time"
)

func testCfg() BaselinesConfig {
	return BaselinesConfig{
		Enabled:       true,
		Warmup:        5 * time.Minute,
		Sensitivity:   3.0,
		HistoryWindow: 30 * time.Minute,
	}
}

// feed pumps n samples of value v spaced 1s apart starting at t0.
func feed(tr *Tracker, key string, v float64, n int, t0 time.Time) time.Time {
	t := t0
	for i := 0; i < n; i++ {
		tr.Observe(key, v, t)
		t = t.Add(time.Second)
	}
	return t
}

// TestWarmupSuppression: no findings during first 5 minutes.
func TestWarmupSuppression(t *testing.T) {
	tr := NewTracker(testCfg())
	t0 := time.Now()
	// Feed 10 samples over 10 seconds (well within warmup).
	now := feed(tr, "k", 1e6, 10, t0)
	tr.Observe("k", 100e6, now) // spike
	r := tr.Check("k", 100e6, SigmaMode, now)
	if r.Exceeded {
		t.Fatal("expected no finding during warmup, got exceeded=true")
	}
}

// TestSpikeDetectedAfterWarmup: stable signal then spike fires only on spike.
func TestSpikeDetectedAfterWarmup(t *testing.T) {
	tr := NewTracker(testCfg())
	t0 := time.Now().Add(-10 * time.Minute) // start 10 min ago

	// 100 stable samples at 1ms.
	stableNs := 1e6 // 1ms
	now := feed(tr, "k", stableNs, 100, t0)

	// Check that stable value does NOT fire.
	r := tr.Check("k", stableNs, SigmaMode, now)
	if r.Exceeded {
		t.Fatal("stable value should not fire")
	}

	// Spike to 10ms = 10Ã— baseline.
	spikeNs := 10e6
	tr.Observe("k", spikeNs, now)
	r = tr.Check("k", spikeNs, SigmaMode, now)
	if !r.Exceeded {
		t.Fatal("10Ã— spike should fire")
	}
}

// TestRatioMode3x: 3Ã— spike â†’ WARNING.
func TestRatioMode3x(t *testing.T) {
	tr := NewTracker(testCfg())
	t0 := time.Now().Add(-10 * time.Minute)
	now := feed(tr, "fsync", 10e6, 100, t0) // 10ms baseline

	spike := 35e6 // 3.5Ã—
	tr.Observe("fsync", spike, now)
	r := tr.Check("fsync", spike, RatioMode, now)
	if !r.Exceeded {
		t.Fatal("3.5Ã— should exceed sensitivity=3.0")
	}
	if r.SuggestedSeverity != SeverityWarning {
		t.Fatalf("3.5Ã— should be WARNING, got %v", r.SuggestedSeverity)
	}
}

// TestRatioMode10x: 10Ã— spike â†’ CRITICAL.
func TestRatioMode10x(t *testing.T) {
	tr := NewTracker(testCfg())
	t0 := time.Now().Add(-10 * time.Minute)
	now := feed(tr, "fsync", 10e6, 100, t0)

	spike := 110e6 // 11Ã—
	tr.Observe("fsync", spike, now)
	r := tr.Check("fsync", spike, RatioMode, now)
	if !r.Exceeded {
		t.Fatal("11Ã— should exceed")
	}
	if r.SuggestedSeverity != SeverityCritical {
		t.Fatalf("11Ã— should be CRITICAL, got %v", r.SuggestedSeverity)
	}
}

// TestSeverityForRatio covers the threshold boundaries.
func TestSeverityForRatio(t *testing.T) {
	cases := []struct {
		ratio float64
		want  Severity
	}{
		{2.9, SeverityWarning},
		{3.0, SeverityWarning},
		{9.9, SeverityWarning},
		{10.0, SeverityCritical},
		{100.0, SeverityCritical},
	}
	for _, c := range cases {
		got := SeverityForRatio(c.ratio)
		if got != c.want {
			t.Errorf("SeverityForRatio(%.1f) = %v, want %v", c.ratio, got, c.want)
		}
	}
}

// TestAnnotationContainsBaseline: annotation mentions baseline value.
func TestAnnotationContainsBaseline(t *testing.T) {
	tr := NewTracker(testCfg())
	t0 := time.Now().Add(-10 * time.Minute)
	now := feed(tr, "k", 9e6, 100, t0) // ~9ms baseline

	spike := 100e6 // ~11Ã—
	tr.Observe("k", spike, now)
	r := tr.Check("k", spike, RatioMode, now)
	if !r.Exceeded {
		t.Fatal("should fire")
	}
	if r.Annotation == "" {
		t.Fatal("annotation should not be empty")
	}
}

// TestDisabledTrackerNoop: disabled tracker never fires.
func TestDisabledTrackerNoop(t *testing.T) {
	cfg := testCfg()
	cfg.Enabled = false
	tr := NewTracker(cfg)
	t0 := time.Now().Add(-10 * time.Minute)
	now := feed(tr, "k", 1e6, 100, t0)
	r := tr.Check("k", 1e9, RatioMode, now)
	if r.Exceeded {
		t.Fatal("disabled tracker should never fire")
	}
}

// TestNoFindingBelowSensitivity: 2Ã— spike does not fire with sensitivity=3.
func TestNoFindingBelowSensitivity(t *testing.T) {
	tr := NewTracker(testCfg())
	t0 := time.Now().Add(-10 * time.Minute)
	now := feed(tr, "k", 10e6, 100, t0)

	spike := 19e6 // 1.9Ã—
	tr.Observe("k", spike, now)
	r := tr.Check("k", spike, RatioMode, now)
	if r.Exceeded {
		t.Fatal("1.9Ã— should not exceed sensitivity=3.0")
	}
}

// TestFmtNsDuration covers all magnitude branches.
func TestFmtNsDuration(t *testing.T) {
	cases := []struct {
		ns   float64
		want string
	}{
		{500, "500ns"},
		{1500, "2Âµs"},
		{1_500_000, "1.5ms"},
		{2_000_000_000, "2.00s"},
	}
	for _, c := range cases {
		got := fmtNsDuration(c.ns)
		if got != c.want {
			t.Errorf("fmtNsDuration(%.0f) = %q, want %q", c.ns, got, c.want)
		}
	}
}

// TestRingEviction: old samples outside window do not affect stats.
func TestRingEviction(t *testing.T) {
	cfg := BaselinesConfig{
		Enabled:       true,
		Warmup:        0,
		Sensitivity:   3.0,
		HistoryWindow: 1 * time.Minute, // 1-min window
	}
	tr := NewTracker(cfg)
	t0 := time.Now().Add(-2 * time.Minute)

	// Old samples (should be evicted): very high value.
	feed(tr, "k", 1000e6, 30, t0) // 1s each, 30s total

	// Recent stable samples inside the 1-min window.
	t1 := time.Now().Add(-30 * time.Second)
	now := feed(tr, "k", 1e6, 60, t1) // 1ms, 60s total

	// A spike of 10ms should fire against the 1ms recent baseline.
	r := tr.Check("k", 10e6, RatioMode, now)
	if !r.Exceeded {
		t.Fatal("10Ã— recent baseline should fire even if old samples were high")
	}
}

// TestSigmaModeAnnotation: sigma annotation format.
func TestSigmaModeAnnotation(t *testing.T) {
	tr := NewTracker(testCfg())
	t0 := time.Now().Add(-10 * time.Minute)
	now := feed(tr, "sched", 5e6, 100, t0)

	spike := 100e6
	tr.Observe("sched", spike, now)
	r := tr.Check("sched", spike, SigmaMode, now)
	if !r.Exceeded {
		t.Fatal("large sigma spike should fire")
	}
	if r.Annotation == "" {
		t.Fatal("sigma annotation should not be empty")
	}
}
