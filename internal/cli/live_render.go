// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// liveStyle is the shared visual vocabulary for kerno trace/watch
// renderers. Pure ANSI escape codes — no TUI dep — but disabled when
// stdout isn't a terminal or NO_COLOR is set, so piped output stays
// clean for CI and SIEM ingestion.
type liveStyle struct {
	color  bool
	bold   string
	dim    string
	cyan   string
	yellow string
	red    string
	green  string
	reset  string
}

func newLiveStyle() liveStyle {
	useColor := isTerminal() && os.Getenv("NO_COLOR") == ""
	if !useColor {
		return liveStyle{}
	}
	return liveStyle{
		color:  true,
		bold:   "\033[1m",
		dim:    "\033[2m",
		cyan:   "\033[36m",
		yellow: "\033[33m",
		red:    "\033[31m",
		green:  "\033[32m",
		reset:  "\033[0m",
	}
}

// liveHeader prints a one-line branded header for a live command.
// Format: ▍ kerno trace syscall · live · 14:32:01
func liveHeader(w io.Writer, s liveStyle, cmd string, suffix string) {
	stamp := time.Now().Format("15:04:05")
	if s.color {
		fmt.Fprintf(w, "%s%s▍ %s%s %s· live · %s%s",
			s.cyan, s.bold, cmd, s.reset, s.dim, stamp, s.reset)
	} else {
		fmt.Fprintf(w, "▍ %s · live · %s", cmd, stamp)
	}
	if suffix != "" {
		if s.color {
			fmt.Fprintf(w, " %s· %s%s", s.dim, suffix, s.reset)
		} else {
			fmt.Fprintf(w, " · %s", suffix)
		}
	}
	fmt.Fprintln(w)
}

// liveFooter prints a Ctrl+C hint with optional event-counter context.
func liveFooter(w io.Writer, s liveStyle, eventsCaptured uint64, elapsed time.Duration) {
	rate := ""
	if elapsed > 0 && eventsCaptured > 0 {
		eps := float64(eventsCaptured) / elapsed.Seconds()
		rate = fmt.Sprintf(" · %s evt/s", humanRate(eps))
	}
	if s.color {
		fmt.Fprintf(w, "%sCtrl+C to stop · %s events%s%s\n",
			s.dim, humanCount(eventsCaptured), rate, s.reset)
	} else {
		fmt.Fprintf(w, "Ctrl+C to stop · %s events%s\n", humanCount(eventsCaptured), rate)
	}
}

// liveColumnHeader formats a row of column labels in cyan-bold so
// header lines are visually distinct from data rows.
func liveColumnHeader(s liveStyle, format string, args ...any) string {
	row := fmt.Sprintf(format, args...)
	if !s.color {
		return row
	}
	return s.cyan + s.bold + row + s.reset
}

// liveDivider returns a fixed-width separator. Width 0 = guess from
// the calling format string, but all current callers pass an explicit
// width.
func liveDivider(s liveStyle, width int) string {
	bar := strings.Repeat("─", width)
	if !s.color {
		return bar
	}
	return s.dim + bar + s.reset
}

// thresholdColor returns the ANSI prefix to color a value based on
// its severity vs. a warning/critical pair. Pass equal warn=critical
// to use a single threshold; the higher one always wins.
func thresholdColor(s liveStyle, value, warn, critical time.Duration) string {
	if !s.color {
		return ""
	}
	switch {
	case critical > 0 && value >= critical:
		return s.red + s.bold
	case warn > 0 && value >= warn:
		return s.yellow
	default:
		return s.green
	}
}

// clearScreen wipes the terminal between live refreshes. Caller decides
// whether they want this — the trace top mode does, the JSON streaming
// mode does not.
func clearScreen(w io.Writer) {
	if isTerminal() {
		fmt.Fprint(w, "\033[H\033[2J")
	}
}
