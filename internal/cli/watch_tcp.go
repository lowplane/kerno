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
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/bpf"
)

func newWatchTCPCmd() *cobra.Command {
	var (
		retransmits  bool
		thresholdRTT time.Duration
		interval     time.Duration
		duration     time.Duration
		output       string
	)

	cmd := &cobra.Command{
		Use:   "tcp",
		Short: "Monitor TCP connections with retransmit and RTT tracking",
		Long: `Watch TCP connection metrics aggregated over configurable time windows.
Displays per-connection RTT percentiles and retransmit counts.`,
		Example: `  # Monitor all TCP connections
  sudo kerno watch tcp

  # Only show connections with retransmits
  sudo kerno watch tcp --retransmits

  # Only show connections with high RTT
  sudo kerno watch tcp --threshold-rtt 5ms --interval 5s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}
			return runWatchTCP(cmd.Context(), watchTCPOpts{
				retransmits:  retransmits,
				thresholdRTT: thresholdRTT,
				interval:     interval,
				duration:     duration,
				output:       output,
			})
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&retransmits, "retransmits", false, "only show connections with retransmits")
	flags.DurationVar(&thresholdRTT, "threshold-rtt", 0, "only show connections with RTT above this")
	flags.DurationVar(&interval, "interval", 2*time.Second, "aggregation/refresh interval")
	flags.DurationVar(&duration, "duration", 0, "total run duration (0 = indefinite)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")

	return cmd
}

type watchTCPOpts struct {
	retransmits  bool
	thresholdRTT time.Duration
	interval     time.Duration
	duration     time.Duration
	output       string
}

// tcpConnKey identifies a TCP connection.
type tcpConnKey struct {
	SAddr string
	DAddr string
	SPort uint16
	DPort uint16
	Comm  string
}

// tcpConnStats aggregates metrics for a single TCP connection.
type tcpConnStats struct {
	RTTs        []time.Duration
	Retransmits uint32
	EventCount  uint64
}

func runWatchTCP(ctx context.Context, opts watchTCPOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()
	loader := bpf.NewTCPMonitorLoader(logger)

	closer, err := loader.Load()
	if err != nil {
		return fmt.Errorf("loading tcp_monitor eBPF program: %w", err)
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
	agg := make(map[tcpConnKey]*tcpConnStats)
	const maxRTTSamples = 10000

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
				event, err := bpf.DecodeTCPEvent(raw.Data)
				if err != nil {
					logger.Debug("decode error", "error", err)
					continue
				}

				key := tcpConnKey{
					SAddr: event.SrcAddr().String(),
					DAddr: event.DstAddr().String(),
					SPort: event.SPort,
					DPort: event.DPort,
					Comm:  event.CommString(),
				}

				mu.Lock()
				stats, ok := agg[key]
				if !ok {
					stats = &tcpConnStats{}
					agg[key] = stats
				}
				stats.EventCount++
				if event.EventType == bpf.TCPEventRetransmit {
					stats.Retransmits += event.Retransmits
				}
				if event.RTTUs > 0 && len(stats.RTTs) < maxRTTSamples {
					stats.RTTs = append(stats.RTTs, event.RTT())
				}
				mu.Unlock()
			}
		}
	}()

	// Render on each interval tick.
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
			agg = make(map[tcpConnKey]*tcpConnStats)
			mu.Unlock()

			entries := filterTCPEntries(snapshot, opts)
			if opts.output == "json" {
				encoder.Encode(tcpSummaryJSON(entries, opts.interval))
			} else {
				renderTCPSummary(entries, opts.interval)
			}
		}
	}
}

type tcpSummaryEntry struct {
	Key    tcpConnKey
	Stats  *tcpConnStats
	RTTP50 time.Duration
	RTTP99 time.Duration
}

func filterTCPEntries(agg map[tcpConnKey]*tcpConnStats, opts watchTCPOpts) []tcpSummaryEntry {
	entries := make([]tcpSummaryEntry, 0, len(agg))
	for key, stats := range agg {
		p50 := percentile(stats.RTTs, 50)
		p99 := percentile(stats.RTTs, 99)

		if opts.retransmits && stats.Retransmits == 0 {
			continue
		}
		if opts.thresholdRTT > 0 && p99 < opts.thresholdRTT {
			continue
		}

		entries = append(entries, tcpSummaryEntry{
			Key:    key,
			Stats:  stats,
			RTTP50: p50,
			RTTP99: p99,
		})
	}

	// Sort by retransmit count desc, then RTT p99 desc.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Stats.Retransmits != entries[j].Stats.Retransmits {
			return entries[i].Stats.Retransmits > entries[j].Stats.Retransmits
		}
		return entries[i].RTTP99 > entries[j].RTTP99
	})

	return entries
}

func renderTCPSummary(entries []tcpSummaryEntry, interval time.Duration) {
	totalEvents := uint64(0)
	for _, e := range entries {
		totalEvents += e.Stats.EventCount
	}

	s := newLiveStyle()
	clearScreen(os.Stdout)
	liveHeader(os.Stdout, s, "kerno watch tcp",
		fmt.Sprintf("%d connections · last %s", len(entries), interval))
	fmt.Println()
	fmt.Println(liveColumnHeader(s, "  %-21s %-21s %10s %10s %8s %-16s",
		"SRC", "DST", "RTT(p50)", "RTT(p99)", "RETRANS", "PROCESS"))
	fmt.Println("  " + liveDivider(s, 88))

	const (
		rttWarn = 5 * time.Millisecond
		rttCrit = 50 * time.Millisecond
	)

	for _, e := range entries {
		src := fmt.Sprintf("%s:%d", e.Key.SAddr, e.Key.SPort)
		dst := fmt.Sprintf("%s:%d", e.Key.DAddr, e.Key.DPort)

		rttP50 := "-"
		rttP99 := "-"
		rttColor := ""
		if len(e.Stats.RTTs) > 0 {
			rttP50 = formatLatency(e.RTTP50)
			rttP99 = formatLatency(e.RTTP99)
			rttColor = thresholdColor(s, e.RTTP99, rttWarn, rttCrit)
		}

		// Retransmits are always concerning — color any non-zero value.
		retxColor := ""
		if e.Stats.Retransmits > 0 && s.color {
			retxColor = s.red + s.bold
		}

		fmt.Printf("  %-21s %-21s %10s %s%10s%s %s%8d%s %-16s\n",
			src, dst, rttP50,
			rttColor, rttP99, s.reset,
			retxColor, e.Stats.Retransmits, s.reset,
			e.Key.Comm)
	}
	fmt.Println()
	liveFooter(os.Stdout, s, totalEvents, interval)
}

type tcpSummaryJSONOut struct {
	Timestamp   string           `json:"timestamp"`
	Interval    string           `json:"interval"`
	Connections []tcpConnJSONOut `json:"connections"`
}

type tcpConnJSONOut struct {
	SrcAddr     string `json:"srcAddr"`
	DstAddr     string `json:"dstAddr"`
	SrcPort     uint16 `json:"srcPort"`
	DstPort     uint16 `json:"dstPort"`
	Comm        string `json:"comm"`
	RTTP50Ns    int64  `json:"rttP50Ns"`
	RTTP99Ns    int64  `json:"rttP99Ns"`
	Retransmits uint32 `json:"retransmits"`
	Events      uint64 `json:"events"`
}

func tcpSummaryJSON(entries []tcpSummaryEntry, interval time.Duration) tcpSummaryJSONOut {
	conns := make([]tcpConnJSONOut, len(entries))
	for i, e := range entries {
		conns[i] = tcpConnJSONOut{
			SrcAddr:     e.Key.SAddr,
			DstAddr:     e.Key.DAddr,
			SrcPort:     e.Key.SPort,
			DstPort:     e.Key.DPort,
			Comm:        e.Key.Comm,
			RTTP50Ns:    e.RTTP50.Nanoseconds(),
			RTTP99Ns:    e.RTTP99.Nanoseconds(),
			Retransmits: e.Stats.Retransmits,
			Events:      e.Stats.EventCount,
		}
	}
	return tcpSummaryJSONOut{
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		Interval:    interval.String(),
		Connections: conns,
	}
}
