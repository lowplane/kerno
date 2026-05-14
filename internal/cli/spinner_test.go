// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProgressBar(t *testing.T) {
	cases := []struct {
		pct, width int
		filled     int
	}{
		{0, 10, 0},
		{50, 10, 5},
		{100, 10, 10},
		{-5, 10, 0},   // clamped to 0
		{150, 10, 10}, // clamped to 100
	}
	for _, c := range cases {
		bar := progressBar(c.pct, c.width)
		if len([]rune(bar)) != c.width {
			t.Errorf("pct=%d width=%d → bar width %d, want %d", c.pct, c.width, len([]rune(bar)), c.width)
		}
		got := strings.Count(bar, "█")
		if got != c.filled {
			t.Errorf("pct=%d → %d filled blocks, want %d", c.pct, got, c.filled)
		}
	}
}

func TestHumanCount(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1.0K"},
		{12500, "12.5K"},
		{1_500_000, "1.5M"},
		{2_300_000_000, "2.3B"},
	}
	for _, c := range cases {
		if got := humanCount(c.in); got != c.want {
			t.Errorf("humanCount(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHumanRate(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{500, "500"},
		{12500, "12.5K"},
		{2_500_000, "2.5M"},
	}
	for _, c := range cases {
		if got := humanRate(c.in); got != c.want {
			t.Errorf("humanRate(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSpinnerRunAndStop(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, true) // noColor for stable output

	s.SetPhase("collecting")
	// counter is read by the spinner goroutine and written by the
	// generator goroutine — atomic prevents the race detector from
	// flagging the data race that production code sees as benign.
	var counter atomic.Uint64
	s.SetEventsFn(counter.Load)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	go func() {
		// Simulate event flow.
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				counter.Add(100)
			}
		}
	}()

	s.Run(ctx, 250*time.Millisecond)
	s.Stop()

	out := buf.String()
	if !strings.Contains(out, "collecting") {
		t.Errorf("output missing phase label; got: %q", out)
	}
	// Should contain at least one progress bar and a percentage like "100%"
	if !strings.Contains(out, "%") {
		t.Errorf("output missing percentage indicator")
	}
}

func TestSpinnerStopIsIdempotent(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, true)
	s.Stop()
	s.Stop() // should not panic
}
