// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	var (
		duration   time.Duration
		exitCode   bool
		continuous bool
		interval   time.Duration
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run a 30-second automated kernel diagnostic",
		Long: `Kerno Doctor collects kernel signals via eBPF for 30 seconds (configurable),
analyzes them against diagnostic rules, and prints a ranked report of findings.

This is the primary entry point for kernel troubleshooting. No configuration needed.`,
		Example: `  # Run a standard 30-second diagnostic
  sudo kerno doctor

  # Quick 10-second check
  sudo kerno doctor --duration 10s

  # Machine-readable output for CI/CD
  sudo kerno doctor --output json --exit-code

  # Continuous monitoring
  sudo kerno doctor --continuous --interval 60s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.Context(), duration, exitCode, continuous, interval)
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", 0, "analysis duration (default: from config, typically 30s)")
	flags.BoolVar(&exitCode, "exit-code", false, "exit 1 if critical findings exist (for CI/CD)")
	flags.BoolVar(&continuous, "continuous", false, "re-run analysis at regular intervals")
	flags.DurationVar(&interval, "interval", 60*time.Second, "interval between runs in continuous mode")

	return cmd
}

func runDoctor(ctx context.Context, duration time.Duration, exitCode bool, continuous bool, interval time.Duration) error {
	// Use config default if no flag override.
	if duration == 0 {
		if cfg != nil {
			duration = cfg.Doctor.Duration
		} else {
			duration = 30 * time.Second
		}
	}

	logger := slog.Default()
	logger.Info("starting kernel diagnostic",
		"duration", duration,
		"continuous", continuous,
	)

	// TODO(phase-3): Implement the full doctor engine pipeline:
	//   1. Load eBPF programs
	//   2. Start collectors
	//   3. Collect signals for `duration`
	//   4. Run diagnostic rules against collected signals
	//   5. Rank findings by severity
	//   6. Render output

	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                     KERNO DOCTOR                        ║")
	fmt.Println("║              Kernel Diagnostic Engine                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Duration:  %s\n", duration)
	fmt.Printf("  Status:    awaiting implementation (Phase 3)\n")
	fmt.Println()
	fmt.Println("  The doctor engine is under construction.")
	fmt.Println("  Follow the roadmap: Phase 1 (eBPF) → Phase 2 (collectors) → Phase 3 (doctor)")
	fmt.Println()

	_ = ctx
	_ = exitCode
	_ = continuous
	_ = interval

	return nil
}
