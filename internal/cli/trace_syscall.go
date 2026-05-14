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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/bpf"
)

func newTraceSyscallCmd() *cobra.Command {
	var (
		filter   string
		pid      int
		top      int
		duration time.Duration
		output   string
	)

	cmd := &cobra.Command{
		Use:   "syscall",
		Short: "Trace syscall latency events",
		Long: `Stream real-time syscall latency events from the kernel via eBPF.
Events include PID, process name, syscall number, latency, and return value.

Use --top to display a refreshing top-N view sorted by latency percentile.`,
		Example: `  # Stream all syscall events
  sudo kerno trace syscall

  # Filter by process
  sudo kerno trace syscall --pid 1234

  # Filter by syscall name
  sudo kerno trace syscall --filter read

  # Top 10 by p99 latency, refreshing every 1s
  sudo kerno trace syscall --top 10`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}
			return runTraceSyscall(cmd.Context(), traceSyscallOpts{
				filter:   filter,
				pid:      pid,
				top:      top,
				duration: duration,
				output:   output,
			})
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&filter, "filter", "", "filter by syscall name or number")
	flags.IntVar(&pid, "pid", 0, "filter by process ID (0 = all)")
	flags.IntVar(&top, "top", 0, "show top N syscalls by latency (0 = stream mode)")
	flags.DurationVar(&duration, "duration", 0, "run for this duration then exit (0 = indefinite)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")

	return cmd
}

type traceSyscallOpts struct {
	filter   string
	pid      int
	top      int
	duration time.Duration
	output   string
}

func runTraceSyscall(ctx context.Context, opts traceSyscallOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()
	loader := bpf.NewSyscallLatencyLoader(logger)

	closer, err := loader.Load()
	if err != nil {
		return fmt.Errorf("loading syscall_latency eBPF program: %w", err)
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

	if opts.top > 0 {
		return traceSyscallTop(ctx, events, opts)
	}
	traceSyscallStream(ctx, events, opts)
	return nil
}

// matchSyscallFilter checks if a syscall event matches the --filter flag.
func matchSyscallFilter(event *bpf.SyscallEvent, filter string) bool {
	if filter == "" {
		return true
	}
	// Match by syscall number.
	if nr, err := strconv.Atoi(filter); err == nil {
		return int(event.SyscallNr) == nr
	}
	// Match by syscall name (case-insensitive).
	name := syscallName(event.SyscallNr)
	return strings.EqualFold(name, filter)
}

func traceSyscallStream(ctx context.Context, events <-chan bpf.RawEvent, opts traceSyscallOpts) {
	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-events:
			if !ok {
				return
			}
			event, err := bpf.DecodeSyscallEvent(raw.Data)
			if err != nil {
				slog.Default().Debug("decode error", "error", err)
				continue
			}

			if opts.pid != 0 && int(event.PID) != opts.pid {
				continue
			}
			if !matchSyscallFilter(event, opts.filter) {
				continue
			}

			if opts.output == "json" {
				encoder.Encode(syscallEventJSON(event))
			} else {
				fmt.Fprintf(os.Stdout, "[%s] PID=%-6d COMM=%-16s SYSCALL=%-16s LATENCY=%-10s RET=%d\n",
					time.Now().Format("15:04:05"),
					event.PID,
					event.CommString(),
					syscallName(event.SyscallNr),
					formatLatency(event.Latency()),
					event.Ret,
				)
			}
		}
	}
}

// syscallTopEntry aggregates latency data for a (syscall, comm) key.
type syscallTopEntry struct {
	SyscallNr uint32
	Name      string
	Comm      string
	Count     uint64
	Latencies []time.Duration
}

func traceSyscallTop(ctx context.Context, events <-chan bpf.RawEvent, opts traceSyscallOpts) error {
	agg := make(map[topKey]*syscallTopEntry)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	const maxSamples = 10000

	for {
		select {
		case <-ctx.Done():
			return nil
		case raw, ok := <-events:
			if !ok {
				return nil
			}
			event, err := bpf.DecodeSyscallEvent(raw.Data)
			if err != nil {
				continue
			}
			if opts.pid != 0 && int(event.PID) != opts.pid {
				continue
			}
			if !matchSyscallFilter(event, opts.filter) {
				continue
			}

			key := topKey{nr: event.SyscallNr, comm: event.CommString()}
			e, ok := agg[key]
			if !ok {
				e = &syscallTopEntry{
					SyscallNr: event.SyscallNr,
					Name:      syscallName(event.SyscallNr),
					Comm:      key.comm,
				}
				agg[key] = e
			}
			e.Count++
			if len(e.Latencies) < maxSamples {
				e.Latencies = append(e.Latencies, event.Latency())
			}

		case <-ticker.C:
			renderSyscallTop(agg, opts.top)
			// Reset for next window.
			agg = make(map[topKey]*syscallTopEntry)
		}
	}
}

type topKey struct {
	nr   uint32
	comm string
}

func renderSyscallTop(agg map[topKey]*syscallTopEntry, n int) {
	entries := make([]*syscallTopEntry, 0, len(agg))
	totalEvents := uint64(0)
	for _, e := range agg {
		entries = append(entries, e)
		totalEvents += e.Count
	}

	// Sort by p99 descending.
	sort.Slice(entries, func(i, j int) bool {
		return percentile(entries[i].Latencies, 99) > percentile(entries[j].Latencies, 99)
	})

	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}

	s := newLiveStyle()
	clearScreen(os.Stdout)
	liveHeader(os.Stdout, s, "kerno trace syscall",
		fmt.Sprintf("top %d by p99 · last 1s", len(entries)))
	fmt.Println()
	fmt.Println(liveColumnHeader(s, "  %-16s %-16s %8s %10s %10s %10s",
		"SYSCALL", "PROCESS", "COUNT", "P50", "P95", "P99"))
	fmt.Println("  " + liveDivider(s, 76))

	// Threshold visual cue: warn at 10ms p99, critical at 100ms p99.
	const (
		warnP99 = 10 * time.Millisecond
		critP99 = 100 * time.Millisecond
	)

	for _, e := range entries {
		p50 := percentile(e.Latencies, 50)
		p95 := percentile(e.Latencies, 95)
		p99 := percentile(e.Latencies, 99)
		color := thresholdColor(s, p99, warnP99, critP99)
		fmt.Printf("  %-16s %-16s %8d %10s %10s %s%10s%s\n",
			e.Name, e.Comm, e.Count,
			formatLatency(p50),
			formatLatency(p95),
			color, formatLatency(p99), s.reset,
		)
	}
	fmt.Println()
	liveFooter(os.Stdout, s, totalEvents, time.Second)
}

// percentile computes the p-th percentile from a slice of durations.
func percentile(data []time.Duration, p int) time.Duration {
	if len(data) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(data))
	copy(sorted, data)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := len(sorted) * p / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

type syscallEventOut struct {
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	TID       uint32 `json:"tid"`
	Comm      string `json:"comm"`
	Syscall   string `json:"syscall"`
	SyscallNr uint32 `json:"syscallNr"`
	LatencyNs uint64 `json:"latencyNs"`
	Ret       uint32 `json:"ret"`
}

func syscallEventJSON(e *bpf.SyscallEvent) syscallEventOut {
	return syscallEventOut{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		PID:       e.PID,
		TID:       e.TID,
		Comm:      e.CommString(),
		Syscall:   syscallName(e.SyscallNr),
		SyscallNr: e.SyscallNr,
		LatencyNs: e.LatencyNs,
		Ret:       e.Ret,
	}
}

// syscallName is a thin alias to bpf.SyscallName so existing CLI code
// continues to work without churn.
func syscallName(nr uint32) string { return bpf.SyscallName(nr) }
