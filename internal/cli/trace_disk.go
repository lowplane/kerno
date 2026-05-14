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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/bpf"
)

func newTraceDiskCmd() *cobra.Command {
	var (
		op        string
		threshold time.Duration
		process   string
		duration  time.Duration
		output    string
	)

	cmd := &cobra.Command{
		Use:   "disk",
		Short: "Trace disk I/O latency events",
		Long: `Stream real-time block I/O events from the kernel via eBPF.
Events include operation type, latency, device, sector, and byte count.`,
		Example: `  # Stream all disk I/O events
  sudo kerno trace disk

  # Only show slow writes
  sudo kerno trace disk --op write --threshold 10ms

  # Filter by process
  sudo kerno trace disk --process postgres`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}
			return runTraceDisk(cmd.Context(), traceDiskOpts{
				op:        op,
				threshold: threshold,
				process:   process,
				duration:  duration,
				output:    output,
			})
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&op, "op", "", "filter by operation: read, write, sync")
	flags.DurationVar(&threshold, "threshold", 0, "only show events above this latency")
	flags.StringVar(&process, "process", "", "filter by process name")
	flags.DurationVar(&duration, "duration", 0, "run for this duration then exit (0 = indefinite)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")

	return cmd
}

type traceDiskOpts struct {
	op        string
	threshold time.Duration
	process   string
	duration  time.Duration
	output    string
}

// matchDiskOp checks if a disk event matches the --op filter.
func matchDiskOp(event *bpf.DiskEvent, filter string) bool {
	if filter == "" {
		return true
	}
	switch strings.ToLower(filter) {
	case "read", "r":
		return event.Op == 'R'
	case "write", "w":
		return event.Op == 'W'
	case "sync", "s":
		return event.Op == 'S'
	default:
		return true
	}
}

// matchDiskProcess checks if a disk event matches the --process filter.
func matchDiskProcess(event *bpf.DiskEvent, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.EqualFold(event.CommString(), filter)
}

func runTraceDisk(ctx context.Context, opts traceDiskOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()
	loader := bpf.NewDiskIOLoader(logger)

	closer, err := loader.Load()
	if err != nil {
		return fmt.Errorf("loading disk_io eBPF program: %w", err)
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
			event, err := bpf.DecodeDiskEvent(raw.Data)
			if err != nil {
				slog.Default().Debug("decode error", "error", err)
				continue
			}

			if !matchDiskOp(event, opts.op) {
				continue
			}
			if opts.threshold > 0 && event.Latency() < opts.threshold {
				continue
			}
			if !matchDiskProcess(event, opts.process) {
				continue
			}

			if opts.output == "json" {
				encoder.Encode(diskEventJSON(event))
			} else {
				fmt.Fprintf(os.Stdout, "[%s] PID=%-6d COMM=%-16s OP=%-5s LATENCY=%-10s DEV=%-6s BYTES=%s\n",
					time.Now().Format("15:04:05"),
					event.PID,
					event.CommString(),
					event.OpString(),
					formatLatency(event.Latency()),
					formatDev(event.Dev),
					formatBytes(uint64(event.NrBytes)),
				)
			}
		}
	}
}

type diskEventOut struct {
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Op        string `json:"op"`
	LatencyNs uint64 `json:"latencyNs"`
	Dev       string `json:"dev"`
	Sector    uint64 `json:"sector"`
	Bytes     uint32 `json:"bytes"`
}

func diskEventJSON(e *bpf.DiskEvent) diskEventOut {
	return diskEventOut{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		PID:       e.PID,
		Comm:      e.CommString(),
		Op:        e.OpString(),
		LatencyNs: e.LatencyNs,
		Dev:       formatDev(e.Dev),
		Sector:    e.Sector,
		Bytes:     e.NrBytes,
	}
}
