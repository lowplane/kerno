// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/doctor"
)

// runDoctorWatch implements the live terminal UI for kerno doctor --watch.
// It uses pure ANSI escape codes to provide a "sticky" view that refreshes
// every cycle, showing new, ongoing, and resolved findings.
func runDoctorWatch(
	ctx context.Context,
	engine *doctor.Engine,
	build collectorBuildResult,
	opts doctorOpts,
	logger *slog.Logger,
) error {
	registry := build.registry
	style := newLiveStyle()
	
	var (
		cycle      int
		start      = time.Now()
		prevDiffed []doctor.DiffedFinding
		keepDuration = 30 * time.Second
	)

	// Start all collectors once.
	if err := registry.StartAll(ctx); err != nil {
		logger.Warn("one or more collectors failed to start", "error", err)
	}
	defer registry.StopAll()

	for {
		cycle++
		cycleStart := time.Now()

		// 1. Render "Collecting" state.
		renderWatchFrame(os.Stdout, style, cycle, start, prevDiffed, nil, true)

		// 2. Wait for collection window.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.duration):
		}

		// 3. Diagnose.
		signals := registry.Signals(opts.duration)
		report, err := engine.Diagnose(ctx, signals)
		if err != nil {
			logger.Warn("diagnosis failed in watch cycle", "cycle", cycle, "error", err)
			continue
		}

		// 4. Diff findings.
		diffed := doctor.Diff(prevDiffed, report.Findings, keepDuration)
		prevDiffed = diffed

		// 5. Render "Results" state.
		renderWatchFrame(os.Stdout, style, cycle, start, diffed, signals, false)

		// 6. Wait for next interval.
		waitDuration := opts.interval - time.Since(cycleStart)
		if waitDuration > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(waitDuration):
			}
		}
	}
}

func renderWatchFrame(
	w *os.File,
	s liveStyle,
	cycle int,
	start time.Time,
	findings []doctor.DiffedFinding,
	signals *collector.Signals,
	collecting bool,
) {
	clearScreen(w)
	
	// 1. Header
	uptime := time.Since(start).Round(time.Second)
	fmt.Fprintf(w, "%s%sKERNO DOCTOR — WATCH%s          cycle %d · uptime %s\n",
		s.cyan, s.bold, s.reset, cycle, uptime)
	fmt.Fprintln(w, liveDivider(s, 72))

	// 2. Pulse Header
	if signals != nil {
		pulse := formatPulse(signals)
		fmt.Fprintf(w, "  %spulse%s  %s\n", s.dim, s.reset, pulse)
	} else {
		fmt.Fprintf(w, "  %spulse%s  %scollecting...%s\n", s.dim, s.reset, s.cyan, s.reset)
	}
	fmt.Fprintln(w, liveDivider(s, 72))

	// 3. Findings
	if len(findings) == 0 && !collecting {
		fmt.Fprintf(w, "  %s✓ All kernel signals nominal%s\n", s.green, s.reset)
	} else {
		// Sort findings by severity (Critical > Warning > Info)
		sort.SliceStable(findings, func(i, j int) bool {
			if findings[i].Finding.Severity != findings[j].Finding.Severity {
				return findings[i].Finding.Severity > findings[j].Finding.Severity
			}
			return findings[i].Status < findings[j].Status
		})

		for _, df := range findings {
			renderFindingLine(w, s, df)
		}
	}

	// 4. Footer
	fmt.Fprintln(w, liveDivider(s, 72))
	fmt.Fprintf(w, "%s[Ctrl+C] quit  [w] watch mode active%s\n", s.dim, s.reset)
}

func renderFindingLine(w *os.File, s liveStyle, df doctor.DiffedFinding) {
	prefix := "  "
	style := s.reset
	suffix := ""

	switch df.Status {
	case doctor.StatusNew:
		prefix = "+ "
		if s.color {
			style = s.green + s.bold
		}
	case doctor.StatusResolved:
		prefix = "- "
		if s.color {
			style = s.dim + "\033[9m" // Strikethrough
		}
		suffix = fmt.Sprintf(" (resolved at %s)", df.ResolvedAt.Format("15:04:05"))
	case doctor.StatusOngoing:
		duration := time.Since(df.FirstSeen).Round(time.Second)
		if duration > 5*time.Second {
			suffix = fmt.Sprintf(" for %s", duration)
		}
	}

	sevLabel := df.Finding.Severity.Icon()
	sevColor := ""
	if s.color {
		switch df.Finding.Severity {
		case doctor.SeverityCritical:
			sevColor = s.red + s.bold
		case doctor.SeverityWarning:
			sevColor = s.yellow
		case doctor.SeverityInfo:
			sevColor = s.cyan
		}
	}

	fmt.Fprintf(w, "%s%s%-8s%s  %-20s  %-25s%s%s\n",
		style, prefix, sevColor+sevLabel+style, s.reset+style,
		df.Finding.Rule, df.Finding.Title, suffix, s.reset)
}

func formatPulse(s *collector.Signals) string {
	var parts []string
	if s.Syscall != nil {
		parts = append(parts, fmt.Sprintf("syscall %s/s", humanRate(float64(s.Syscall.TotalCount)/s.Duration.Seconds())))
	}
	if s.Sched != nil {
		parts = append(parts, fmt.Sprintf("sched %s/s", humanRate(float64(s.Sched.TotalCount)/s.Duration.Seconds())))
	}
	if s.DiskIO != nil {
		totalIO := s.DiskIO.TotalReads + s.DiskIO.TotalWrites + s.DiskIO.TotalSyncs
		parts = append(parts, fmt.Sprintf("disk %s/s", humanRate(float64(totalIO)/s.Duration.Seconds())))
	}
	if s.TCP != nil {
		parts = append(parts, fmt.Sprintf("tcp %s/s", humanRate(float64(s.TCP.TotalRetransmits)/s.Duration.Seconds())))
	}
	if s.OOM != nil && s.OOM.Count > 0 {
		parts = append(parts, fmt.Sprintf("oom %d", s.OOM.Count))
	}
	return strings.Join(parts, " · ")
}
