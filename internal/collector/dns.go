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
// dnsFailureTimeout is how long we wait for a response before marking a
// DNS query as failed. Matches the issue spec (5s).
dnsFailureTimeout = 5 * time.Second

// maxDNSConsumers caps the per-process tracking table to prevent unbounded growth.
maxDNSConsumers = 512
)

// dnsQueryKey tracks an in-flight DNS query.
type dnsQueryKey struct {
pid     uint32
queryID uint16
}

// dnsInFlight is a pending DNS send waiting for its matching recv.
type dnsInFlight struct {
sentAt time.Time
comm   string
}

// dnsProcessAgg holds per-process DNS counters.
type dnsProcessAgg struct {
pid      uint32
comm     string
requests uint64
failures uint64
}

// DNSCollector consumes dns_monitor eBPF events and aggregates
// per-pod/process DNS metrics into a DNSSnapshot.
type DNSCollector struct {
logger *slog.Logger
loader *bpf.DNSMonitorLoader

mu           sync.Mutex
inflight     map[dnsQueryKey]*dnsInFlight
latencyHist  *aggregator.Histogram
totalReqs    uint64
totalResps   uint64
totalFails   uint64
windowStart  time.Time
processes    map[uint32]*dnsProcessAgg // keyed by pid

cancelFn context.CancelFunc
done     chan struct{}
}

// NewDNSCollector creates a new DNS collector.
func NewDNSCollector(logger *slog.Logger, loader *bpf.DNSMonitorLoader) *DNSCollector {
return &DNSCollector{
logger:      logger.With("collector", "dns"),
loader:      loader,
inflight:    make(map[dnsQueryKey]*dnsInFlight),
latencyHist: aggregator.New(),
windowStart: time.Now(),
processes:   make(map[uint32]*dnsProcessAgg),
done:        make(chan struct{}),
}
}

// Name implements Collector.
func (c *DNSCollector) Name() string { return "dns" }

// Start implements Collector.
func (c *DNSCollector) Start(ctx context.Context) error {
runCtx, cancel := context.WithCancel(ctx)
c.cancelFn = cancel

ch, err := c.loader.Events(runCtx)
if err != nil {
cancel()
return fmt.Errorf("opening dns events: %w", err)
}

go c.consume(runCtx, ch)
go c.reapLoop(runCtx)
return nil
}

// Stop implements Collector.
func (c *DNSCollector) Stop() {
if c.cancelFn != nil {
c.cancelFn()
}
select {
case <-c.done:
case <-time.After(2 * time.Second):
c.logger.Warn("dns collector did not stop within timeout")
}
}

func (c *DNSCollector) consume(ctx context.Context, ch <-chan bpf.RawEvent) {
defer close(c.done)
for {
select {
case <-ctx.Done():
return
case raw, ok := <-ch:
if !ok {
return
}
event, err := bpf.DecodeDNSEvent(raw.Data)
if err != nil {
c.logger.Debug("dns decode error", "error", err)
continue
}
c.record(event)
}
}
}

// reapLoop periodically expires in-flight queries that never got a response.
func (c *DNSCollector) reapLoop(ctx context.Context) {
ticker := time.NewTicker(dnsFailureTimeout)
defer ticker.Stop()
for {
select {
case <-ctx.Done():
return
case now := <-ticker.C:
c.reapExpired(now)
}
}
}

func (c *DNSCollector) reapExpired(now time.Time) {
c.mu.Lock()
defer c.mu.Unlock()
for key, inf := range c.inflight {
if now.Sub(inf.sentAt) >= dnsFailureTimeout {
c.totalFails++
if p := c.getOrCreateProcess(key.pid, inf.comm); p != nil {
p.failures++
}
delete(c.inflight, key)
}
}
}

func (c *DNSCollector) record(event *bpf.DNSEvent) {
c.mu.Lock()
defer c.mu.Unlock()

comm := event.CommString()
key := dnsQueryKey{pid: event.PID, queryID: event.QueryID}

switch event.EventType {
case bpf.DNSEventSend:
c.totalReqs++
if p := c.getOrCreateProcess(event.PID, comm); p != nil {
p.requests++
}
// Only track if we have room.
if len(c.inflight) < 65536 {
c.inflight[key] = &dnsInFlight{
sentAt: time.Unix(0, int64(event.TimestampNs)),
comm:   comm,
}
}

case bpf.DNSEventRecv:
c.totalResps++
if inf, ok := c.inflight[key]; ok {
latencyNs := uint64(event.TimestampNs) - uint64(inf.sentAt.UnixNano())
// Sanity check: only record if latency is under 30s.
if latencyNs < uint64(30*time.Second) {
c.latencyHist.Record(latencyNs)
}
delete(c.inflight, key)
}
}
}

func (c *DNSCollector) getOrCreateProcess(pid uint32, comm string) *dnsProcessAgg {
if p, ok := c.processes[pid]; ok {
return p
}
if len(c.processes) >= maxDNSConsumers {
return nil
}
p := &dnsProcessAgg{pid: pid, comm: comm}
c.processes[pid] = p
return p
}

// Snapshot implements Collector. Returns *DNSSnapshot.
func (c *DNSCollector) Snapshot() any {
c.mu.Lock()
defer c.mu.Unlock()

elapsed := time.Since(c.windowStart).Seconds()
if elapsed < 1 {
elapsed = 1
}

latSnap := c.latencyHist.Snapshot()

// Build top consumers list.
procs := make([]*dnsProcessAgg, 0, len(c.processes))
for _, p := range c.processes {
procs = append(procs, p)
}
sort.Slice(procs, func(i, j int) bool {
return procs[i].requests > procs[j].requests
})
limit := 10
if len(procs) < limit {
limit = len(procs)
}
consumers := make([]DNSConsumerEntry, 0, limit)
for _, p := range procs[:limit] {
consumers = append(consumers, DNSConsumerEntry{
PID:      p.pid,
Comm:     p.comm,
Requests: p.requests,
Failures: p.failures,
})
}

var failureRate float64
if c.totalReqs > 0 {
failureRate = float64(c.totalFails) / float64(c.totalReqs) * 100.0
}

return &DNSSnapshot{
RequestRate:    float64(c.totalReqs) / elapsed,
ResponseRate:   float64(c.totalResps) / elapsed,
FailureRate:    failureRate,
TotalRequests:  c.totalReqs,
TotalResponses: c.totalResps,
TotalFailures:  c.totalFails,
Latency: Percentiles{
P50: time.Duration(latSnap.Percentile(50)),
P95: time.Duration(latSnap.Percentile(95)),
P99: time.Duration(latSnap.Percentile(99)),
Max: time.Duration(latSnap.Max()),
},
TopConsumers: consumers,
}
}
