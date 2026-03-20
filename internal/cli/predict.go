// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/lowplane/kerno/internal/collector"
	"github.com/lowplane/kerno/internal/doctor"
)

func newPredictCmd() *cobra.Command {
	var (
		snapshots int
		interval  time.Duration
	)

	cmd := &cobra.Command{
		Use:   "predict",
		Short: "Predict kernel-level failures before they happen",
		Long: `Kerno Predict collects multiple signal snapshots over time, analyzes trends,
and predicts failures before they occur using linear extrapolation.

It detects:
- FD exhaustion (process hitting ulimit)
- Disk I/O saturation (latency trending toward critical)
- CPU scheduler degradation (runqueue delay increasing)
- TCP retransmit storms (retransmit rate climbing)

No AI required — predictions are deterministic. AI enrichment can be added
with --ai for cross-signal correlation.`,
		Example: `  # Default: 3 snapshots over 30s
  sudo kerno predict

  # More snapshots for better accuracy
  sudo kerno predict --snapshots 5 --interval 15s

  # Quick check
  sudo kerno predict --snapshots 2 --interval 5s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPredict(cmd.Context(), predictOpts{
				snapshots: snapshots,
				interval:  interval,
			})
		},
	}

	flags := cmd.Flags()
	flags.IntVar(&snapshots, "snapshots", 3, "number of signal snapshots to collect")
	flags.DurationVar(&interval, "interval", 10*time.Second, "interval between snapshots")

	return cmd
}

type predictOpts struct {
	snapshots int
	interval  time.Duration
}

func runPredict(ctx context.Context, opts predictOpts) error {
	logger := slog.Default()

	if opts.snapshots < 2 {
		return fmt.Errorf("need at least 2 snapshots for prediction (got %d)", opts.snapshots)
	}

	// Create collector registry.
	registry := collector.NewRegistry(logger)

	// TODO(phase-2): Register live collectors here once they are implemented.

	totalDuration := time.Duration(opts.snapshots) * opts.interval
	fmt.Fprintf(os.Stderr, "Collecting %d snapshots over %s (interval: %s)...\n",
		opts.snapshots, totalDuration, opts.interval)

	// Collect snapshots.
	var snapshots []*collector.Signals
	for i := 0; i < opts.snapshots; i++ {
		// Wait for the interval.
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "Interrupted — analyzing %d/%d snapshots.\n", len(snapshots), opts.snapshots)
			goto analyze
		case <-time.After(opts.interval):
		}

		signals := registry.Signals(opts.interval)
		snapshots = append(snapshots, signals)
		fmt.Fprintf(os.Stderr, "  Snapshot %d/%d collected\n", i+1, opts.snapshots)
	}

analyze:
	if len(snapshots) < 2 {
		fmt.Fprintln(os.Stderr, "Not enough snapshots for prediction (need at least 2).")
		return nil
	}

	// Run prediction analysis.
	report := doctor.Predict(snapshots)

	// Render the prediction report.
	renderPredictionReport(report)

	return nil
}

func renderPredictionReport(report *doctor.PredictionReport) {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                   KERNO PREDICT                         ║")
	fmt.Println("║            Failure Prediction Report                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Printf("  Snapshots analyzed:  %d\n", report.SnapshotCount)
	fmt.Printf("  Analysis window:     %s\n", report.AnalysisWindow)
	fmt.Println()

	if len(report.Predictions) == 0 {
		fmt.Println("  No failures predicted — all trends are stable or improving.")
		fmt.Println()
		fmt.Println("  Run `kerno predict --snapshots 5 --interval 15s` for deeper analysis.")
		fmt.Println()
		return
	}

	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Printf(" PREDICTIONS  (%d potential failure(s) detected)\n", len(report.Predictions))
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Println()

	for i, p := range report.Predictions {
		urgency := "[WATCH]"
		if p.TimeToImpact < 5*time.Minute {
			urgency = "[IMMINENT]"
		} else if p.TimeToImpact < 30*time.Minute {
			urgency = "[SOON]    "
		}

		fmt.Printf("  %d. %s %s\n", i+1, urgency, p.Title)
		fmt.Printf("     Signal:      %s\n", p.Signal)
		fmt.Printf("     ETA:         %s\n", formatETA(p.TimeToImpact))
		fmt.Printf("     Confidence:  %.0f%%\n", p.Confidence*100)
		fmt.Printf("     Current:     %s\n", p.CurrentValue)
		fmt.Printf("     Trend:       %s\n", p.TrendRate)
		fmt.Printf("     Limit:       %s\n", p.Limit)
		if len(p.Fix) > 0 {
			fmt.Printf("     Fix:         → %s\n", p.Fix[0])
			for _, fix := range p.Fix[1:] {
				fmt.Printf("                  → %s\n", fix)
			}
		}
		fmt.Println()
	}

	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("  Run `kerno doctor` for a full diagnostic of current state")
	fmt.Println("  Run `kerno predict --snapshots 5` for higher confidence")
	fmt.Println()
}

func formatETA(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("~%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("~%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("~%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
