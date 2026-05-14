// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/chaos"
)

func newChaosCmd() *cobra.Command {
	var (
		induce    string
		list      bool
		duration  time.Duration
		intensity string
		yes       bool
	)

	cmd := &cobra.Command{
		Use:   "chaos",
		Short: "Inject synthetic kernel-level failures (for demos and rule-firing tests)",
		Long: `Kerno Chaos induces controlled, in-process synthetic failures so that
"kerno doctor" rules can be exercised end-to-end without waiting for a real
incident. Every scenario pairs with at least one doctor rule.

Useful for:
  - Recording demo GIFs ("induce → detect → explain")
  - CI tests that verify a rule fires when its target signal is induced
  - Manual smoke tests of new diagnostic rules

Safety: every scenario is in-process, self-bounded by --duration, and
cleans up after itself (temp files removed, goroutines stopped, memory
freed). Nothing on the host is permanently modified.`,
		Example: `  # List available scenarios
  kerno chaos --list

  # Run the headline cascade for 30s
  kerno chaos --induce cascade

  # FD leak at high intensity for 1 minute
  kerno chaos --induce fd-leak --intensity high --duration 1m

  # Skip the confirmation prompt (for CI)
  kerno chaos --induce cpu --yes`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if list {
				return runChaosList(cmd.OutOrStdout())
			}
			if induce == "" {
				return fmt.Errorf("must specify --induce <scenario> or --list")
			}
			return runChaosInduce(cmd.Context(), chaosOpts{
				name:      induce,
				duration:  duration,
				intensity: chaos.ParseIntensity(intensity),
				yes:       yes,
			})
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&induce, "induce", "", "scenario to induce (see --list)")
	flags.BoolVar(&list, "list", false, "list available scenarios and exit")
	flags.DurationVar(&duration, "duration", 30*time.Second, "total run time")
	flags.StringVar(&intensity, "intensity", "medium", "low | medium | high")
	flags.BoolVarP(&yes, "yes", "y", false, "skip the safety prompt")

	return cmd
}

type chaosOpts struct {
	name      string
	duration  time.Duration
	intensity chaos.Intensity
	yes       bool
}

func runChaosList(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer func() { _ = tw.Flush() }()

	fmt.Fprintln(tw, "SCENARIO\tPAIRED RULE\tDESCRIPTION")
	for _, s := range chaos.List() {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name(), s.PairedRule(), s.Description())
	}
	return nil
}

func runChaosInduce(ctx context.Context, opts chaosOpts) error {
	scenario, ok := chaos.Get(opts.name)
	if !ok {
		return fmt.Errorf("unknown scenario %q (run 'kerno chaos --list')", opts.name)
	}

	if !opts.yes {
		fmt.Fprintf(os.Stderr,
			"WARNING: this will load this machine for %s.\n"+
				"  scenario:  %s\n"+
				"  rule:      %s expected to fire\n"+
				"  intensity: %s\n\n"+
				"Press Enter to continue or Ctrl+C to abort: ",
			opts.duration, scenario.Name(), scenario.PairedRule(), opts.intensity)

		reader := bufio.NewReader(os.Stdin)
		if _, err := reader.ReadString('\n'); err != nil {
			return fmt.Errorf("aborted: %w", err)
		}
	}

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.Default()
	return chaos.Run(ctx, opts.name, chaos.Options{
		Intensity: opts.intensity,
		Duration:  opts.duration,
		Logger:    logger,
		Out:       os.Stderr,
	})
}
