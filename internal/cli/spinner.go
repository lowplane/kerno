// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Spinner renders a single in-place progress line during the doctor's
// collection window. It shows the current phase, elapsed time vs.
// total, and a live event counter so the user knows the binary is
// alive and how much data is flowing.
//
// Pure ANSI escape codes — no dependency on a TUI library.
type Spinner struct {
	w        io.Writer
	noColor  bool
	frames   []string
	interval time.Duration

	mu       sync.Mutex
	phase    string
	eventsFn func() uint64
	stopped  atomic.Bool
}

// NewSpinner constructs a spinner that writes to w. If noColor is true,
// it skips color codes but still uses the cursor-control sequences that
// rewrite the same line.
func NewSpinner(w io.Writer, noColor bool) *Spinner {
	return &Spinner{
		w:        w,
		noColor:  noColor,
		frames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		interval: 100 * time.Millisecond,
		phase:    "starting",
		eventsFn: func() uint64 { return 0 },
	}
}

// SetPhase updates the phase label rendered in the next tick.
func (s *Spinner) SetPhase(phase string) {
	s.mu.Lock()
	s.phase = phase
	s.mu.Unlock()
}

// SetEventsFn registers a callback the spinner calls every tick to
// fetch the current event count. Pass a closure that reads from the
// collector registry.
func (s *Spinner) SetEventsFn(fn func() uint64) {
	s.mu.Lock()
	s.eventsFn = fn
	s.mu.Unlock()
}

// Run blocks until ctx is canceled, redrawing the status line on each
// tick. Total is the configured collection duration so the user sees
// elapsed/total. Caller-provided ctx terminates the spinner.
func (s *Spinner) Run(ctx context.Context, total time.Duration) {
	start := time.Now()
	frame := 0
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.clear()
			return
		case <-ticker.C:
			s.draw(frame, time.Since(start), total)
			frame = (frame + 1) % len(s.frames)
		}
	}
}

func (s *Spinner) draw(frame int, elapsed, total time.Duration) {
	s.mu.Lock()
	phase := s.phase
	events := s.eventsFn()
	s.mu.Unlock()

	pct := 0
	if total > 0 {
		pct = int(elapsed * 100 / total)
		if pct > 100 {
			pct = 100
		}
	}

	bar := progressBar(pct, 24)
	spin := s.frames[frame%len(s.frames)]
	rate := ""
	if elapsed > 0 && events > 0 {
		eps := float64(events) / elapsed.Seconds()
		rate = fmt.Sprintf("  %s evt/s", humanRate(eps))
	}

	if s.noColor {
		// Plain text path: cursor up + erase line.
		fmt.Fprintf(s.w, "\r\033[K %s  [%s] %3d%%  %s  %s evt%s",
			spin, bar, pct, phase, humanCount(events), rate)
	} else {
		fmt.Fprintf(s.w,
			"\r\033[K \033[36m%s\033[0m  [\033[36m%s\033[0m] \033[1m%3d%%\033[0m  \033[2m%s\033[0m  \033[33m%s\033[0m evt\033[2m%s\033[0m",
			spin, bar, pct, phase, humanCount(events), rate)
	}
}

func (s *Spinner) clear() {
	if s.stopped.Swap(true) {
		return
	}
	// Erase the spinner line and return cursor to col 0.
	fmt.Fprint(s.w, "\r\033[K")
}

// Stop ensures the line is cleared. Safe to call multiple times.
func (s *Spinner) Stop() {
	s.clear()
}

// progressBar returns a fixed-width Unicode bar where pct fills
// proportionally. Uses block-drawing chars for a smooth-looking bar.
func progressBar(pct, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := pct * width / 100
	bar := make([]rune, 0, width)
	for i := 0; i < filled; i++ {
		bar = append(bar, '█')
	}
	for i := filled; i < width; i++ {
		bar = append(bar, '░')
	}
	return string(bar)
}

// humanCount formats integers with thousands grouping (12,481).
func humanCount(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1_000_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000.0)
	}
	if n < 1_000_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000.0)
	}
	return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000.0)
}

// humanRate formats events-per-second compactly.
func humanRate(eps float64) string {
	switch {
	case eps < 1000:
		return fmt.Sprintf("%.0f", eps)
	case eps < 1_000_000:
		return fmt.Sprintf("%.1fK", eps/1000.0)
	default:
		return fmt.Sprintf("%.1fM", eps/1_000_000.0)
	}
}
