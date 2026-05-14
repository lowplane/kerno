// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector/aggregator"
)

const (
	DefaultTCPConnCap            = 8192
	MaxTCPConnEntriesPerSnapshot = 32
)

// TCPCollector consumes tcp_monitor eBPF events and aggregates
// per-connection metrics (RTT distribution, retransmit count) into a
// TCPSnapshot.
type TCPCollector struct {
	logger *slog.Logger
	loader *bpf.TCPMonitorLoader
	cap    int

	mu               sync.Mutex
	conns            *aggregator.LRU[tcpConnKey, *tcpConnAgg]
	rttHist          *aggregator.Histogram
	totalRetransmits uint64
	totalEvents      uint64

	cancelFn context.CancelFunc
	done     chan struct{}
}

type tcpConnKey struct {
	saddr uint32
	daddr uint32
	sport uint16
	dport uint16
	comm  string
}

type tcpConnAgg struct {
	srcAddr     string
	dstAddr     string
	sport       uint16
	dport       uint16
	comm        string
	rttHist     *aggregator.Histogram
	retransmits uint32
}

// NewTCPCollector creates a TCP collector with default capacity.
func NewTCPCollector(logger *slog.Logger, loader *bpf.TCPMonitorLoader) *TCPCollector {
	return NewTCPCollectorWithCap(logger, loader, DefaultTCPConnCap)
}

// NewTCPCollectorWithCap allows tuning the per-connection cap.
func NewTCPCollectorWithCap(logger *slog.Logger, loader *bpf.TCPMonitorLoader, connCap int) *TCPCollector {
	return &TCPCollector{
		logger:  logger.With("collector", "tcp"),
		loader:  loader,
		cap:     connCap,
		conns:   aggregator.NewLRU[tcpConnKey, *tcpConnAgg](connCap),
		rttHist: aggregator.New(),
		done:    make(chan struct{}),
	}
}

// Name implements Collector.
func (c *TCPCollector) Name() string { return "tcp" }

// Start implements Collector.
func (c *TCPCollector) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel

	ch, err := c.loader.Events(runCtx)
	if err != nil {
		cancel()
		return fmt.Errorf("opening tcp events: %w", err)
	}

	go c.consume(runCtx, ch)
	return nil
}

// Stop implements Collector.
func (c *TCPCollector) Stop() {
	if c.cancelFn != nil {
		c.cancelFn()
	}
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.logger.Warn("collector did not stop within timeout")
	}
}

func (c *TCPCollector) consume(ctx context.Context, ch <-chan bpf.RawEvent) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			event, err := bpf.DecodeTCPEvent(raw.Data)
			if err != nil {
				c.logger.Debug("decode error", "error", err)
				continue
			}
			c.record(event)
		}
	}
}

func (c *TCPCollector) record(event *bpf.TCPEvent) {
	key := tcpConnKey{
		saddr: event.SAddr,
		daddr: event.DAddr,
		sport: event.SPort,
		dport: event.DPort,
		comm:  event.CommString(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.totalEvents++

	agg, ok := c.conns.Get(key)
	if !ok {
		agg = &tcpConnAgg{
			srcAddr: event.SrcAddr().String(),
			dstAddr: event.DstAddr().String(),
			sport:   event.SPort,
			dport:   event.DPort,
			comm:    key.comm,
			rttHist: aggregator.New(),
		}
		c.conns.Put(key, agg)
	}

	if event.RTTUs > 0 {
		rttNs := uint64(event.RTTUs) * 1000
		agg.rttHist.Record(rttNs)
		c.rttHist.Record(rttNs)
	}
	if event.EventType == bpf.TCPEventRetransmit {
		// Each tracepoint fire = one retransmitted skb. The Retransmits
		// field in the event payload was reserved for userspace
		// aggregation that never landed; counting events directly is
		// the correct kernel-truth signal.
		agg.retransmits++
		c.totalRetransmits++
	}
}

// Snapshot implements Collector. Returns *TCPSnapshot.
func (c *TCPCollector) Snapshot() any {
	c.mu.Lock()
	totalEvents := c.totalEvents
	totalRetransmits := c.totalRetransmits
	rttSnap := c.rttHist.Snapshot()
	connCount := c.conns.Len()

	type entry struct {
		key tcpConnKey
		agg *tcpConnAgg
	}
	all := make([]entry, 0, connCount)
	c.conns.Range(func(k tcpConnKey, v *tcpConnAgg) bool {
		all = append(all, entry{k, v})
		return true
	})
	c.mu.Unlock()

	// Rank by retransmits desc, then RTT p99 desc.
	sort.Slice(all, func(i, j int) bool {
		if all[i].agg.retransmits != all[j].agg.retransmits {
			return all[i].agg.retransmits > all[j].agg.retransmits
		}
		return all[i].agg.rttHist.Percentile(99) > all[j].agg.rttHist.Percentile(99)
	})

	limit := MaxTCPConnEntriesPerSnapshot
	if len(all) < limit {
		limit = len(all)
	}
	top := make([]TCPConnectionEntry, 0, limit)
	for _, e := range all[:limit] {
		top = append(top, TCPConnectionEntry{
			SrcAddr:     e.agg.srcAddr,
			DstAddr:     e.agg.dstAddr,
			SrcPort:     e.agg.sport,
			DstPort:     e.agg.dport,
			Comm:        e.agg.comm,
			RTT:         time.Duration(e.agg.rttHist.Percentile(99)),
			Retransmits: e.agg.retransmits,
		})
	}

	var rate float64
	if totalEvents > 0 {
		rate = float64(totalRetransmits) / float64(totalEvents) * 100.0
	}

	return &TCPSnapshot{
		ActiveConnections: connCount,
		TotalRetransmits:  totalRetransmits,
		RetransmitRate:    rate,
		RTT: Percentiles{
			P50: time.Duration(rttSnap.Percentile(50)),
			P95: time.Duration(rttSnap.Percentile(95)),
			P99: time.Duration(rttSnap.Percentile(99)),
			Max: time.Duration(rttSnap.Max()),
		},
		TopRetransmitters: top,
	}
}
