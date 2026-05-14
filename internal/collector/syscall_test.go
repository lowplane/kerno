// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
)

func newSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// makeSyscallEvent constructs a SyscallEvent with the given comm name
// and latency, leaving other fields at sensible defaults.
func makeSyscallEvent(comm string, syscallNr uint32, latencyNs uint64, ret uint32) *bpf.SyscallEvent {
	e := &bpf.SyscallEvent{
		SyscallNr: syscallNr,
		LatencyNs: latencyNs,
		Ret:       ret,
		PID:       1234,
	}
	copy(e.Comm[:], comm)
	return e
}

func TestSyscallCollectorAggregates(t *testing.T) {
	c := NewSyscallCollector(newSilentLogger(), nil)

	// 100 events for (read, app) with monotonic latency.
	for i := uint64(1); i <= 100; i++ {
		c.record(makeSyscallEvent("app", 0, i*1000, 0))
	}
	// 50 events for (write, app) with higher latency.
	for i := uint64(1); i <= 50; i++ {
		c.record(makeSyscallEvent("app", 1, i*10000, 0))
	}

	snap := c.Snapshot().(*SyscallSnapshot)
	if snap.TotalCount != 150 {
		t.Errorf("TotalCount = %d, want 150", snap.TotalCount)
	}
	if len(snap.Entries) != 2 {
		t.Fatalf("Entries = %d, want 2", len(snap.Entries))
	}

	// Top entry should be the higher-latency syscall.
	top := snap.Entries[0]
	if top.SyscallNr != 1 {
		t.Errorf("top SyscallNr = %d, want 1 (write — higher p99)", top.SyscallNr)
	}
	if top.Name != "write" {
		t.Errorf("top Name = %q, want %q", top.Name, "write")
	}
	if top.Comm != "app" {
		t.Errorf("top Comm = %q, want %q", top.Comm, "app")
	}
	if top.Latency.P99 == 0 {
		t.Error("top Latency.P99 should be non-zero")
	}
	if top.Latency.P50 > top.Latency.P99 {
		t.Errorf("p50 (%v) > p99 (%v) — non-monotonic", top.Latency.P50, top.Latency.P99)
	}
}

func TestSyscallCollectorErrorTracking(t *testing.T) {
	c := NewSyscallCollector(newSilentLogger(), nil)

	for i := 0; i < 80; i++ {
		c.record(makeSyscallEvent("app", 0, 1000, 0)) // success
	}
	for i := 0; i < 20; i++ {
		// -EAGAIN encoded as a uint32 errno return.
		c.record(makeSyscallEvent("app", 0, 1000, 0xFFFFFFF5))
	}

	snap := c.Snapshot().(*SyscallSnapshot)
	if len(snap.Entries) != 1 {
		t.Fatalf("Entries = %d, want 1", len(snap.Entries))
	}
	entry := snap.Entries[0]
	if entry.Count != 100 {
		t.Errorf("Count = %d, want 100", entry.Count)
	}
	if entry.ErrorCount != 20 {
		t.Errorf("ErrorCount = %d, want 20", entry.ErrorCount)
	}
}

func TestSyscallCollectorCapEnforced(t *testing.T) {
	const keyCap = 8
	c := NewSyscallCollectorWithCap(newSilentLogger(), nil, keyCap)

	// Generate more unique (syscall, comm) keys than the cap.
	for i := 0; i < keyCap*2; i++ {
		c.record(makeSyscallEvent("comm-"+string(rune('a'+i)), uint32(i), 1000, 0))
	}

	// LRU bound should keep us under the cap.
	if got := c.keys.Len(); got > keyCap {
		t.Errorf("keys.Len() = %d, want <= %d (cap)", got, keyCap)
	}
	if got := c.keys.Evicted(); got == 0 {
		t.Error("expected non-zero Evicted count after exceeding cap")
	}
}

func TestSyscallCollectorEmptySnapshot(t *testing.T) {
	c := NewSyscallCollector(newSilentLogger(), nil)
	snap := c.Snapshot().(*SyscallSnapshot)
	if snap.TotalCount != 0 {
		t.Errorf("empty TotalCount = %d, want 0", snap.TotalCount)
	}
	if len(snap.Entries) != 0 {
		t.Errorf("empty Entries len = %d, want 0", len(snap.Entries))
	}
}

func TestSyscallCollectorEntriesCapped(t *testing.T) {
	c := NewSyscallCollector(newSilentLogger(), nil)

	// Generate many more keys than MaxSyscallEntriesPerSnapshot.
	for i := 0; i < MaxSyscallEntriesPerSnapshot*2; i++ {
		c.record(makeSyscallEvent("app", uint32(i), uint64(i+1)*1000, 0))
	}

	snap := c.Snapshot().(*SyscallSnapshot)
	if len(snap.Entries) > MaxSyscallEntriesPerSnapshot {
		t.Errorf("Entries = %d, exceeds MaxSyscallEntriesPerSnapshot (%d)",
			len(snap.Entries), MaxSyscallEntriesPerSnapshot)
	}
}

// makeDiskEvent builds a disk event of the given op type.
func makeDiskEvent(op byte, latencyNs uint64, bytes uint32) *bpf.DiskEvent {
	return &bpf.DiskEvent{
		LatencyNs: latencyNs,
		NrBytes:   bytes,
		Op:        op,
	}
}

func TestDiskIOCollectorPerOpAggregation(t *testing.T) {
	c := NewDiskIOCollector(newSilentLogger(), nil)

	for i := uint64(1); i <= 50; i++ {
		c.record(makeDiskEvent('R', i*1000, 4096))
	}
	for i := uint64(1); i <= 100; i++ {
		c.record(makeDiskEvent('W', i*5000, 4096))
	}
	for i := uint64(1); i <= 10; i++ {
		c.record(makeDiskEvent('S', i*100000, 0))
	}

	snap := c.Snapshot().(*DiskIOSnapshot)
	if snap.TotalReads != 50 {
		t.Errorf("TotalReads = %d, want 50", snap.TotalReads)
	}
	if snap.TotalWrites != 100 {
		t.Errorf("TotalWrites = %d, want 100", snap.TotalWrites)
	}
	if snap.TotalSyncs != 10 {
		t.Errorf("TotalSyncs = %d, want 10", snap.TotalSyncs)
	}
	// Sync latencies are highest, so SyncLatency.P99 should be the largest.
	if !(snap.SyncLatency.P99 > snap.WriteLatency.P99 && snap.WriteLatency.P99 > snap.ReadLatency.P99) {
		t.Errorf("expected sync > write > read by p99, got R=%v W=%v S=%v",
			snap.ReadLatency.P99, snap.WriteLatency.P99, snap.SyncLatency.P99)
	}
	if snap.ReadBytes != 50*4096 {
		t.Errorf("ReadBytes = %d, want %d", snap.ReadBytes, 50*4096)
	}
}

func makeOOMEvent(comm string, pid uint32) *bpf.OOMEvent {
	e := &bpf.OOMEvent{PID: pid}
	copy(e.Comm[:], comm)
	return e
}

func TestOOMCollectorEventLog(t *testing.T) {
	c := NewOOMCollector(newSilentLogger(), nil)

	c.record(makeOOMEvent("victim-a", 100))
	c.record(makeOOMEvent("victim-b", 200))

	snap := c.Snapshot().(*OOMSnapshot)
	if snap.Count != 2 {
		t.Errorf("Count = %d, want 2", snap.Count)
	}
	if len(snap.Events) != 2 {
		t.Fatalf("Events len = %d, want 2", len(snap.Events))
	}
	if snap.Events[0].Comm != "victim-a" {
		t.Errorf("Events[0].Comm = %q, want %q", snap.Events[0].Comm, "victim-a")
	}
}

func TestOOMCollectorBoundedLog(t *testing.T) {
	c := NewOOMCollector(newSilentLogger(), nil)

	// Fire well past the cap; the snapshot should stay bounded.
	for i := 0; i < MaxOOMEvents*2; i++ {
		c.record(makeOOMEvent("loop", uint32(i)))
	}

	snap := c.Snapshot().(*OOMSnapshot)
	if snap.Count > MaxOOMEvents {
		t.Errorf("Count = %d, exceeds MaxOOMEvents (%d)", snap.Count, MaxOOMEvents)
	}
}

func TestFDCollectorGrowthRate(t *testing.T) {
	c := NewFDCollector(newSilentLogger(), nil)
	c.startTime = time.Now().Add(-1 * time.Second) // pretend 1s elapsed

	for i := 0; i < 100; i++ {
		c.record(&bpf.FDEvent{PID: 1, Op: bpf.FDOpOpen})
	}
	for i := 0; i < 30; i++ {
		c.record(&bpf.FDEvent{PID: 1, Op: bpf.FDOpClose})
	}

	snap := c.Snapshot().(*FDSnapshot)
	if snap.TotalOpens != 100 {
		t.Errorf("TotalOpens = %d, want 100", snap.TotalOpens)
	}
	if snap.TotalCloses != 30 {
		t.Errorf("TotalCloses = %d, want 30", snap.TotalCloses)
	}
	if snap.NetDelta != 70 {
		t.Errorf("NetDelta = %d, want 70", snap.NetDelta)
	}
	// Growth rate ≈ 70/1s = 70 fds/sec.
	if snap.GrowthRate < 50 {
		t.Errorf("GrowthRate = %v, want > 50/sec", snap.GrowthRate)
	}
}

func TestSchedCollectorRanksByDelay(t *testing.T) {
	c := NewSchedCollector(newSilentLogger(), nil)

	// "fast" PID 1 with low delays.
	for i := uint64(1); i <= 100; i++ {
		c.record(&bpf.SchedEvent{PID: 1, RunqDelayNs: i * 1000})
	}
	// "slow" PID 2 with high delays.
	for i := uint64(1); i <= 100; i++ {
		c.record(&bpf.SchedEvent{PID: 2, RunqDelayNs: i * 1_000_000})
	}

	snap := c.Snapshot().(*SchedSnapshot)
	if snap.TotalCount != 200 {
		t.Errorf("TotalCount = %d, want 200", snap.TotalCount)
	}
	if len(snap.TopDelayed) < 2 {
		t.Fatalf("TopDelayed len = %d, want >= 2", len(snap.TopDelayed))
	}
	if snap.TopDelayed[0].PID != 2 {
		t.Errorf("TopDelayed[0].PID = %d, want 2 (slower process)", snap.TopDelayed[0].PID)
	}
}

func TestRegistrySignalsRoundTrip(t *testing.T) {
	r := newTestRegistry()
	sc := NewSyscallCollector(newSilentLogger(), nil)
	for i := uint64(1); i <= 50; i++ {
		sc.record(makeSyscallEvent("app", 0, i*1000, 0))
	}

	if err := r.Register(sc); err != nil {
		t.Fatal(err)
	}

	signals := r.Signals(30 * time.Second)
	if signals.Syscall == nil {
		t.Fatal("expected non-nil Syscall snapshot")
	}
	if signals.Syscall.TotalCount != 50 {
		t.Errorf("Syscall.TotalCount = %d, want 50", signals.Syscall.TotalCount)
	}
}
