// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
)

// memoryBudgetMB is the Phase 2 DoD target: collectors must keep heap
// usage under this many MB under sustained 100K events/s load.
const memoryBudgetMB = 50

// readPeakMB is the heap-in-use ceiling we treat as the working-set
// memory cost. Reported via t.Logf so CI surfaces the actual number.
func readHeapInuseMB() float64 {
	runtime.GC()
	runtime.GC() // second pass cleans up free-but-uncollected objects
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapInuse) / (1024 * 1024)
}

// TestCollectorMemoryHighCardinalityBurst pumps a burst of events
// through every collector with cardinality far exceeding each LRU cap.
// The invariant under test: no matter how many unique keys are seen,
// the working set stays bounded by the cap × per-key size.
func TestCollectorMemoryHighCardinalityBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in -short mode")
	}

	sc := NewSyscallCollector(newSilentLogger(), nil)
	tc := NewTCPCollector(newSilentLogger(), nil)
	oc := NewOOMCollector(newSilentLogger(), nil)
	dc := NewDiskIOCollector(newSilentLogger(), nil)
	schc := NewSchedCollector(newSilentLogger(), nil)
	fc := NewFDCollector(newSilentLogger(), nil)

	baseMB := readHeapInuseMB()

	const events = 2_000_000

	// 16K unique comms so we churn the LRU well past its 4K cap.
	const distinctComms = 16_000
	const distinctSyscalls = 400

	for i := 0; i < events; i++ {
		comm := fmt.Sprintf("p%05d", i%distinctComms)
		nr := uint32(i % distinctSyscalls)

		sc.record(makeSyscallEvent(comm, nr, uint64((i%1000)+1)*1000, 0))

		schc.record(&bpf.SchedEvent{
			PID:         uint32(i % distinctComms),
			RunqDelayNs: uint64((i % 500) + 1),
		})

		dc.record(makeDiskEvent("RWS"[i%3], uint64((i%1000)+1)*1000, 4096))

		fc.record(&bpf.FDEvent{
			PID: uint32(i % distinctComms),
			Op:  bpf.FDOp((i % 2) + 1),
		})

		// TCP: vary 4-tuple to grow connection map.
		tcpEvent := &bpf.TCPEvent{
			SAddr:     uint32(i),
			DAddr:     uint32(i + 1),
			SPort:     uint16(i % 65535),
			DPort:     80,
			RTTUs:     uint32((i % 500) + 1),
			EventType: bpf.TCPEventRTT,
		}
		copy(tcpEvent.Comm[:], comm)
		tc.record(tcpEvent)

		// OOM is intentionally rare — exercise the bounded-log path.
		if i%10000 == 0 {
			oc.record(makeOOMEvent(comm, uint32(i)))
		}
	}

	peakMB := readHeapInuseMB()
	growthMB := peakMB - baseMB
	t.Logf("burst: %d events through 6 collectors → heap growth %.2f MB (peak %.2f MB)",
		events, growthMB, peakMB)

	if growthMB > memoryBudgetMB {
		t.Errorf("heap grew %.2f MB, exceeds %d MB budget", growthMB, memoryBudgetMB)
	}

	// Force snapshots to ensure they don't reveal hidden allocations.
	for _, snapper := range []interface {
		Snapshot() any
	}{sc, tc, oc, dc, schc, fc} {
		_ = snapper.Snapshot()
	}

	// LRU should be at its cap, not unbounded.
	if got := sc.keys.Len(); got > sc.cap {
		t.Errorf("syscall LRU Len=%d > cap=%d", got, sc.cap)
	}
	if got := tc.conns.Len(); got > tc.cap {
		t.Errorf("tcp LRU Len=%d > cap=%d", got, tc.cap)
	}
	if got := schc.keys.Len(); got > schc.cap {
		t.Errorf("sched LRU Len=%d > cap=%d", got, schc.cap)
	}
	if got := fc.keys.Len(); got > fc.cap {
		t.Errorf("fd LRU Len=%d > cap=%d", got, fc.cap)
	}
}

// TestCollectorMemorySustained100Kps exercises the working set under
// sustained 100K events/s load for a few seconds. It rate-limits via
// a token loop instead of time.Sleep per event so the achieved rate
// matches the target on slower CI runners.
func TestCollectorMemorySustained100Kps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in -short mode")
	}

	sc := NewSyscallCollector(newSilentLogger(), nil)
	dc := NewDiskIOCollector(newSilentLogger(), nil)
	schc := NewSchedCollector(newSilentLogger(), nil)

	baseMB := readHeapInuseMB()

	const targetRate = 100_000 // events/sec
	const duration = 3 * time.Second
	const batchSize = 1000
	tickInterval := time.Second / (targetRate / batchSize)

	var (
		totalEvents int
		mu          sync.Mutex
		stopAt      = time.Now().Add(duration)
	)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	commTemplate := func(i int) string { return fmt.Sprintf("p%04d", i%4000) }

	start := time.Now()
	for time.Now().Before(stopAt) {
		<-ticker.C
		for j := 0; j < batchSize; j++ {
			i := totalEvents + j
			comm := commTemplate(i)
			sc.record(makeSyscallEvent(comm, uint32(i%200), uint64((i%1000)+1)*1000, 0))
			schc.record(&bpf.SchedEvent{PID: uint32(i % 4000), RunqDelayNs: uint64((i % 500) + 1)})
			dc.record(makeDiskEvent("RWS"[i%3], uint64((i%1000)+1)*1000, 4096))
		}
		mu.Lock()
		totalEvents += batchSize
		mu.Unlock()
	}
	elapsed := time.Since(start)

	achievedRate := float64(totalEvents*3) / elapsed.Seconds() // 3 collectors per batch
	peakMB := readHeapInuseMB()
	growthMB := peakMB - baseMB

	t.Logf("sustained: %d events × 3 collectors in %v = %.0f events/s; heap growth %.2f MB",
		totalEvents, elapsed.Round(time.Millisecond), achievedRate, growthMB)

	if achievedRate < float64(targetRate)*0.8 {
		t.Logf("WARNING: achieved rate %.0f/s is far below %d target — runner may be slow", achievedRate, targetRate)
	}
	if growthMB > memoryBudgetMB {
		t.Errorf("heap grew %.2f MB under %.0f events/s, exceeds %d MB budget",
			growthMB, achievedRate, memoryBudgetMB)
	}
}

// TestCollectorConcurrentRecord verifies the lock contention path is
// correct under multi-goroutine record load. It does not measure
// memory but adds confidence that the sustained test isn't masking
// concurrency bugs.
func TestCollectorConcurrentRecord(t *testing.T) {
	sc := NewSyscallCollector(newSilentLogger(), nil)

	const goroutines = 16
	const eventsPerGoroutine = 100_000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				sc.record(makeSyscallEvent(
					fmt.Sprintf("p%04d", (seed*eventsPerGoroutine+i)%4000),
					uint32(i%100),
					uint64((i%1000)+1)*1000,
					0,
				))
			}
		}(g)
	}
	wg.Wait()

	snap := sc.Snapshot().(*SyscallSnapshot)
	expected := uint64(goroutines * eventsPerGoroutine)
	if snap.TotalCount != expected {
		t.Errorf("TotalCount = %d, want %d (concurrent writes lost events)",
			snap.TotalCount, expected)
	}
}
