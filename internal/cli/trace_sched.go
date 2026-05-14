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
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/bpf"
)

func newTraceSchedCmd() *cobra.Command {
	var (
		threshold time.Duration
		duration  time.Duration
		output    string
	)

	cmd := &cobra.Command{
		Use:   "sched",
		Short: "Trace CPU scheduler delay events",
		Long: `Stream real-time scheduler run-queue delay events from the kernel via eBPF.
Shows how long processes wait on the CPU run queue before being scheduled.`,
		Example: `  # Stream all scheduler events
  sudo kerno trace sched

  # Only show delays above 5ms
  sudo kerno trace sched --threshold 5ms

  # Run for 30 seconds
  sudo kerno trace sched --threshold 1ms --duration 30s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}
			return runTraceSched(cmd.Context(), traceSchedOpts{
				threshold: threshold,
				duration:  duration,
				output:    output,
			})
		},
	}

	flags := cmd.Flags()
	flags.DurationVar(&threshold, "threshold", 0, "only show events with runqueue delay above this")
	flags.DurationVar(&duration, "duration", 0, "run for this duration then exit (0 = indefinite)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")

	return cmd
}

type traceSchedOpts struct {
	threshold time.Duration
	duration  time.Duration
	output    string
}

func runTraceSched(ctx context.Context, opts traceSchedOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()
	loader := bpf.NewSchedDelayLoader(logger)

	closer, err := loader.Load()
	if err != nil {
		return fmt.Errorf("loading sched_delay eBPF program: %w", err)
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

	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			return nil
		case raw, ok := <-events:
			if !ok {
				return nil
			}
			event, err := bpf.DecodeSchedEvent(raw.Data)
			if err != nil {
				slog.Default().Debug("decode error", "error", err)
				continue
			}

			if opts.threshold > 0 && event.RunqDelay() < opts.threshold {
				continue
			}

			if opts.output == "json" {
				encoder.Encode(schedEventJSON(event))
			} else {
				fmt.Fprintf(os.Stdout, "[%s] PID=%-6d COMM=%-16s CPU=%-3d RUNQ_DELAY=%s\n",
					time.Now().Format("15:04:05"),
					event.PID,
					event.CommString(),
					event.CPU,
					formatLatency(event.RunqDelay()),
				)
			}
		}
	}
}

type schedEventOut struct {
	Timestamp   string `json:"timestamp"`
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	CPU         uint32 `json:"cpu"`
	RunqDelayNs uint64 `json:"runqDelayNs"`
}

func schedEventJSON(e *bpf.SchedEvent) schedEventOut {
	return schedEventOut{
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		PID:         e.PID,
		Comm:        e.CommString(),
		CPU:         e.CPU,
		RunqDelayNs: e.RunqDelayNs,
	}
}
