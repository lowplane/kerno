// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/optiqor/kerno/internal/bpf"
)

// LabelCardinalityLimit caps the number of unique label combinations
// per metric to prevent unbounded memory growth from high-cardinality
// labels (e.g., per-PID processes).
const LabelCardinalityLimit = 5000

// Bridge reads raw eBPF events and feeds them into Prometheus metrics.
// Each loaded BPF program gets a goroutine that decodes events and
// updates the corresponding metric.
type Bridge struct {
	logger *slog.Logger

	mu       sync.Mutex
	seen     map[string]int // metric name → cardinality count
	cancelFn context.CancelFunc
}

// NewBridge creates a metrics bridge.
func NewBridge(logger *slog.Logger) *Bridge {
	return &Bridge{
		logger: logger,
		seen:   make(map[string]int),
	}
}

// Start launches a goroutine per loader that reads events and records metrics.
// It blocks until all goroutines are started, then returns. Call Stop() or
// cancel the parent context to shut them down.
func (b *Bridge) Start(ctx context.Context, loaders []bpf.Loader) {
	ctx, cancel := context.WithCancel(ctx)
	b.cancelFn = cancel

	for _, l := range loaders {
		ch, err := l.Events(ctx)
		if err != nil {
			b.logger.Debug("skipping metrics bridge for unloaded program",
				"program", l.Name())
			continue
		}
		go b.consume(ctx, l.Name(), ch)
		b.logger.Info("metrics bridge started", "program", l.Name())
	}
}

// Stop cancels the bridge context, causing all consume goroutines to exit.
func (b *Bridge) Stop() {
	if b.cancelFn != nil {
		b.cancelFn()
	}
}

// cardinalityOK returns true if the metric has not exceeded the label
// cardinality limit. This is a simple counter — not a true cardinality
// tracker (would need an LRU or HyperLogLog for production), but
// sufficient as a safety valve.
func (b *Bridge) cardinalityOK(metric string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seen[metric]++
	return b.seen[metric] <= LabelCardinalityLimit
}

func (b *Bridge) consume(ctx context.Context, name string, ch <-chan bpf.RawEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			CollectorEventsTotal.WithLabelValues(name).Inc()
			b.record(name, raw)
		}
	}
}

func (b *Bridge) record(name string, raw bpf.RawEvent) {
	switch name {
	case "syscall_latency":
		b.recordSyscall(raw)
	case "tcp_monitor":
		b.recordTCP(raw)
	case "oom_track":
		b.recordOOM(raw)
	case "disk_io":
		b.recordDiskIO(raw)
	case "sched_delay":
		b.recordSchedDelay(raw)
	case "fd_track":
		b.recordFD(raw)
	default:
		// Unknown program — count it but don't decode.
	}
}

func (b *Bridge) recordSyscall(raw bpf.RawEvent) {
	event, err := bpf.DecodeSyscallEvent(raw.Data)
	if err != nil {
		CollectorErrorsTotal.WithLabelValues("syscall_latency").Inc()
		return
	}
	if !b.cardinalityOK("syscall") {
		return
	}
	comm := event.CommString()
	sc := bpf.SyscallName(event.SyscallNr)
	SyscallDuration.WithLabelValues(sc, comm).Observe(float64(event.LatencyNs))
	SyscallTotal.WithLabelValues(sc, comm).Inc()
}

func (b *Bridge) recordTCP(raw bpf.RawEvent) {
	event, err := bpf.DecodeTCPEvent(raw.Data)
	if err != nil {
		CollectorErrorsTotal.WithLabelValues("tcp_monitor").Inc()
		return
	}
	if !b.cardinalityOK("tcp") {
		return
	}
	src := event.SrcAddr().String()
	dst := event.DstAddr().String()
	comm := event.CommString()

	TCPConnectionsTotal.WithLabelValues(src, dst, comm).Inc()

	if event.RTTUs > 0 {
		TCPRTT.WithLabelValues(src, dst, comm).Observe(float64(event.RTTUs) * 1000) // us → ns
	}
	if event.Retransmits > 0 {
		TCPRetransmitsTotal.WithLabelValues(src, dst, comm).Add(float64(event.Retransmits))
	}
}

func (b *Bridge) recordOOM(raw bpf.RawEvent) {
	event, err := bpf.DecodeOOMEvent(raw.Data)
	if err != nil {
		CollectorErrorsTotal.WithLabelValues("oom_track").Inc()
		return
	}
	comm := event.CommString()
	OOMKillsTotal.WithLabelValues(comm).Inc()
}

func (b *Bridge) recordDiskIO(raw bpf.RawEvent) {
	event, err := bpf.DecodeDiskEvent(raw.Data)
	if err != nil {
		CollectorErrorsTotal.WithLabelValues("disk_io").Inc()
		return
	}
	if !b.cardinalityOK("disk_io") {
		return
	}
	dev := formatDev(event.Dev)
	op := event.OpString()
	DiskIODuration.WithLabelValues(dev, op).Observe(float64(event.LatencyNs))
	DiskIOBytesTotal.WithLabelValues(dev, op).Add(float64(event.NrBytes))
}

func (b *Bridge) recordSchedDelay(raw bpf.RawEvent) {
	event, err := bpf.DecodeSchedEvent(raw.Data)
	if err != nil {
		CollectorErrorsTotal.WithLabelValues("sched_delay").Inc()
		return
	}
	if !b.cardinalityOK("sched_delay") {
		return
	}
	comm := event.CommString()
	SchedDelay.WithLabelValues(comm).Observe(float64(event.RunqDelayNs))
}

func (b *Bridge) recordFD(raw bpf.RawEvent) {
	event, err := bpf.DecodeFDEvent(raw.Data)
	if err != nil {
		CollectorErrorsTotal.WithLabelValues("fd_track").Inc()
		return
	}
	if !b.cardinalityOK("fd_track") {
		return
	}
	comm := event.CommString()
	switch event.Op {
	case bpf.FDOpOpen:
		FDOpenTotal.WithLabelValues(comm).Inc()
	case bpf.FDOpClose:
		FDCloseTotal.WithLabelValues(comm).Inc()
	}
}

// formatDev formats a kernel dev_t (major<<20 | minor) into "major:minor".
func formatDev(dev uint32) string {
	major := dev >> 20
	minor := dev & ((1 << 20) - 1)
	return fmt.Sprintf("%d:%d", major, minor)
}
