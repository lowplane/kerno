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

func newWatchOOMCmd() *cobra.Command {
	var (
		threshold int64
		alert     bool
		duration  time.Duration
		output    string
	)

	cmd := &cobra.Command{
		Use:   "oom",
		Short: "Monitor OOM kill events",
		Long: `Watch for OOM (Out of Memory) kill events in real-time.
Each OOM event is displayed immediately — these are critical events that
indicate the kernel killed a process to free memory.`,
		Example: `  # Watch for all OOM kills
  sudo kerno watch oom

  # Watch with alert banner
  sudo kerno watch oom --alert

  # Filter by OOM score threshold
  sudo kerno watch oom --threshold 500 --alert`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}
			return runWatchOOM(cmd.Context(), watchOOMOpts{
				threshold: threshold,
				alert:     alert,
				duration:  duration,
				output:    output,
			})
		},
	}

	flags := cmd.Flags()
	flags.Int64Var(&threshold, "threshold", 0, "only show events with oom_score above this")
	flags.BoolVar(&alert, "alert", false, "print alert banner on each OOM event")
	flags.DurationVar(&duration, "duration", 0, "total run duration (0 = indefinite)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")

	return cmd
}

type watchOOMOpts struct {
	threshold int64
	alert     bool
	duration  time.Duration
	output    string
}

// matchOOMThreshold checks if an OOM event passes the --threshold filter.
func matchOOMThreshold(event *bpf.OOMEvent, threshold int64) bool {
	if threshold == 0 {
		return true
	}
	return int64(event.OOMScore) >= threshold
}

func runWatchOOM(ctx context.Context, opts watchOOMOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()
	loader := bpf.NewOOMTrackLoader(logger)

	closer, err := loader.Load()
	if err != nil {
		return fmt.Errorf("loading oom_track eBPF program: %w", err)
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

	fmt.Fprintf(os.Stderr, "Watching for OOM kill events... (Ctrl+C to stop)\n")

	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			return nil
		case raw, ok := <-events:
			if !ok {
				return nil
			}
			event, err := bpf.DecodeOOMEvent(raw.Data)
			if err != nil {
				logger.Debug("decode error", "error", err)
				continue
			}

			if !matchOOMThreshold(event, opts.threshold) {
				continue
			}

			if opts.output == "json" {
				encoder.Encode(oomEventJSON(event))
			} else {
				renderOOMEvent(event, opts.alert)
			}
		}
	}
}

func renderOOMEvent(event *bpf.OOMEvent, alert bool) {
	now := time.Now().Format("15:04:05")
	rssBytes := event.RSSPages * 4096
	totalBytes := event.TotalPages * 4096

	if alert {
		fmt.Println()
		fmt.Println("  !! OOM KILL DETECTED !!")
		fmt.Println()
	}

	fmt.Printf("[%s] VICTIM=%-16s PID=%-6d TRIGGERED_BY=PID:%-6d OOM_SCORE=%-5d RSS=%s TOTAL=%s\n",
		now,
		event.CommString(),
		event.PID,
		event.TriggeredPID,
		event.OOMScore,
		formatBytes(rssBytes),
		formatBytes(totalBytes),
	)
}

type oomEventOut struct {
	Timestamp    string `json:"timestamp"`
	Victim       string `json:"victim"`
	PID          uint32 `json:"pid"`
	TriggeredPID uint32 `json:"triggeredPid"`
	OOMScore     int32  `json:"oomScore"`
	RSSPages     uint64 `json:"rssPages"`
	TotalPages   uint64 `json:"totalPages"`
	RSSBytes     uint64 `json:"rssBytes"`
	TotalBytes   uint64 `json:"totalBytes"`
}

func oomEventJSON(e *bpf.OOMEvent) oomEventOut {
	return oomEventOut{
		Timestamp:    time.Now().Format(time.RFC3339Nano),
		Victim:       e.CommString(),
		PID:          e.PID,
		TriggeredPID: e.TriggeredPID,
		OOMScore:     e.OOMScore,
		RSSPages:     e.RSSPages,
		TotalPages:   e.TotalPages,
		RSSBytes:     e.RSSPages * 4096,
		TotalBytes:   e.TotalPages * 4096,
	}
}
