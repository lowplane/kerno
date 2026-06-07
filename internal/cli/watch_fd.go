// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/bpf"
)

func newWatchFDCmd() *cobra.Command {
	var (
		threshold float64
		interval  time.Duration
		duration  time.Duration
		output    string
	)

	cmd := &cobra.Command{
		Use:   "fd",
		Short: "Monitor file descriptor leak detection",
		Long: `Watch file descriptor open/close events aggregated over time windows.
Alerts when per-process FD growth rate exceeds the threshold, indicating
a potential file descriptor leak.`,
		Example: `  # Monitor FD leaks (default threshold: 10 FDs/sec)
  sudo kerno watch fd

  # Lower threshold for early detection
  sudo kerno watch fd --threshold 5

  # Custom interval
  sudo kerno watch fd --threshold 5 --interval 10s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}
			return runWatchFD(cmd.Context(), watchFDOpts{
				threshold: threshold,
				interval:  interval,
				duration:  duration,
				output:    output,
			})
		},
	}

	flags := cmd.Flags()
	flags.Float64Var(&threshold, "threshold", 10.0, "alert when FD growth rate exceeds this (FDs/sec)")
	flags.DurationVar(&interval, "interval", 5*time.Second, "aggregation/refresh interval")
	flags.DurationVar(&duration, "duration", 0, "total run duration (0 = indefinite)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")

	return cmd
}

type watchFDOpts struct {
	threshold float64
	interval  time.Duration
	duration  time.Duration
	output    string
}

// fdProcKey identifies a process for FD aggregation.
type fdProcKey struct {
	PID  uint32
	Comm string
}

// fdProcStats tracks FD opens and closes for a process.
type fdProcStats struct {
	Opens  uint64
	Closes uint64
}

func runWatchFD(ctx context.Context, opts watchFDOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()
	loader := bpf.NewFDTrackLoader(logger)

	closer, err := loader.Load()
	if err != nil {
		return fmt.Errorf("loading fd_track eBPF program: %w", err)
	}
	defer closer.Close()

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if opts.duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.duration)
		defer cancel()
	}

	events, err := loader.Events(ctx)
	if err != nil {
		return fmt.Errorf("reading events: %w", err)
	}

	var mu sync.Mutex
	agg := make(map[fdProcKey]*fdProcStats)

	// Event reader goroutine.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case raw, ok := <-events:
				if !ok {
					return
				}
				event, err := bpf.DecodeFDEvent(raw.Data)
				if err != nil {
					logger.Debug("decode error", "error", err)
					continue
				}

				key := fdProcKey{PID: event.PID, Comm: event.CommString()}

				mu.Lock()
				stats, ok := agg[key]
				if !ok {
					stats = &fdProcStats{}
					agg[key] = stats
				}
				switch event.Op {
				case bpf.FDOpOpen:
					stats.Opens++
				case bpf.FDOpClose:
					stats.Closes++
				}
				mu.Unlock()
			}
		}
	}()

	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()

	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			mu.Lock()
			snapshot := agg
			agg = make(map[fdProcKey]*fdProcStats)
			mu.Unlock()

			entries := computeFDEntries(snapshot, opts.interval, opts.threshold)
			if opts.output == "json" {
				encoder.Encode(fdSummaryJSON(entries, opts.interval, opts.threshold))
			} else {
				renderFDSummary(entries, opts.interval, opts.threshold)
			}
		}
	}
}

type fdSummaryEntry struct {
	Key        fdProcKey
	Opens      uint64
	Closes     uint64
	NetDelta   int64
	GrowthRate float64
}

// computeFDEntries calculates growth rates and filters by threshold.
func computeFDEntries(agg map[fdProcKey]*fdProcStats, interval time.Duration, threshold float64) []fdSummaryEntry {
	secs := interval.Seconds()
	entries := make([]fdSummaryEntry, 0, len(agg))

	for key, stats := range agg {
		netDelta := int64(stats.Opens) - int64(stats.Closes)
		growthRate := float64(netDelta) / secs

		if growthRate < threshold {
			continue
		}

		entries = append(entries, fdSummaryEntry{
			Key:        key,
			Opens:      stats.Opens,
			Closes:     stats.Closes,
			NetDelta:   netDelta,
			GrowthRate: growthRate,
		})
	}

	// Sort by growth rate descending.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].GrowthRate > entries[j].GrowthRate
	})

	return entries
}

func renderFDSummary(entries []fdSummaryEntry, interval time.Duration, threshold float64) {
	if isTerminal() {
		fmt.Print("\033[H\033[2J")
	}

	fmt.Printf("[%s] FD Leak Watch (last %s) — %d processes above threshold (%.1f FDs/sec)\n",
		time.Now().Format("15:04:05"), interval, len(entries), threshold)
	fmt.Printf("%-8s %-16s %8s %8s %10s %10s\n",
		"PID", "COMM", "OPENS", "CLOSES", "NET_DELTA", "RATE(/s)")
	fmt.Println(strings.Repeat("─", 66))

	if len(entries) == 0 {
		fmt.Println("  No processes exceeding threshold — FD usage looks healthy.")
	}

	for _, e := range entries {
		leak := ""
		if e.GrowthRate >= threshold {
			leak = " !! LEAK"
		}
		fmt.Printf("%-8d %-16s %8d %8d %+10d %10.1f%s\n",
			e.Key.PID, e.Key.Comm, e.Opens, e.Closes, e.NetDelta, e.GrowthRate, leak)
	}
	fmt.Println()
}

type fdSummaryJSONOut struct {
	Timestamp string          `json:"timestamp"`
	Interval  string          `json:"interval"`
	Threshold float64         `json:"threshold"`
	Processes []fdProcJSONOut `json:"processes"`
}

type fdProcJSONOut struct {
	PID        uint32  `json:"pid"`
	Comm       string  `json:"comm"`
	Opens      uint64  `json:"opens"`
	Closes     uint64  `json:"closes"`
	NetDelta   int64   `json:"netDelta"`
	GrowthRate float64 `json:"growthRate"`
}

func fdSummaryJSON(entries []fdSummaryEntry, interval time.Duration, threshold float64) fdSummaryJSONOut {
	procs := make([]fdProcJSONOut, len(entries))

	for i, e := range entries {
		procs[i] = fdProcJSONOut{
			PID:        e.Key.PID,
			Comm:       e.Key.Comm,
			Opens:      e.Opens,
			Closes:     e.Closes,
			NetDelta:   e.NetDelta,
			GrowthRate: e.GrowthRate,
		}
	}

	return fdSummaryJSONOut{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Interval:  interval.String(),
		Threshold: threshold,
		Processes: procs,
	}
}
