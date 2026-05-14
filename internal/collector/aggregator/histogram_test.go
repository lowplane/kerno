// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"math/rand"
	"sync"
	"testing"
)

func TestHistogramEmpty(t *testing.T) {
	h := New()
	if got := h.Count(); got != 0 {
		t.Errorf("Count() = %d, want 0", got)
	}
	if got := h.Percentile(50); got != 0 {
		t.Errorf("Percentile(50) on empty = %d, want 0", got)
	}
	if got := h.Mean(); got != 0 {
		t.Errorf("Mean() on empty = %v, want 0", got)
	}
}

func TestHistogramRecord(t *testing.T) {
	h := New()
	for _, v := range []uint64{100, 200, 300, 400, 500} {
		h.Record(v)
	}
	if got := h.Count(); got != 5 {
		t.Errorf("Count() = %d, want 5", got)
	}
	if got := h.Sum(); got != 1500 {
		t.Errorf("Sum() = %d, want 1500", got)
	}
	if got := h.Min(); got != 100 {
		t.Errorf("Min() = %d, want 100", got)
	}
	if got := h.Max(); got != 500 {
		t.Errorf("Max() = %d, want 500", got)
	}
}

func TestHistogramPercentilesMonotonic(t *testing.T) {
	h := New()
	for i := 1; i <= 10000; i++ {
		h.Record(uint64(i))
	}
	p50 := h.Percentile(50)
	p95 := h.Percentile(95)
	p99 := h.Percentile(99)
	if !(p50 <= p95 && p95 <= p99) {
		t.Errorf("non-monotonic percentiles: p50=%d p95=%d p99=%d", p50, p95, p99)
	}
	if p99 > h.Max() {
		t.Errorf("p99 (%d) exceeds Max (%d)", p99, h.Max())
	}
	if p50 < h.Min() {
		t.Errorf("p50 (%d) below Min (%d)", p50, h.Min())
	}
}

func TestHistogramPercentileWithinBucketBound(t *testing.T) {
	// All samples in [1024, 2047] → bucket 10 covers [2^10, 2^11).
	h := New()
	for i := 1024; i < 2048; i++ {
		h.Record(uint64(i))
	}
	p99 := h.Percentile(99)
	if p99 < 1024 || p99 >= 2048 {
		t.Errorf("p99 = %d, want in [1024, 2048)", p99)
	}
}

func TestHistogramMinMaxClamp(t *testing.T) {
	h := New()
	h.Record(50_000_000) // 50ms
	h.Record(60_000_000)
	h.Record(70_000_000)
	p100 := h.Percentile(100)
	if p100 != h.Max() {
		t.Errorf("Percentile(100) = %d, want Max=%d", p100, h.Max())
	}
	p0 := h.Percentile(0)
	if p0 != h.Min() {
		t.Errorf("Percentile(0) = %d, want Min=%d", p0, h.Min())
	}
}

func TestHistogramMerge(t *testing.T) {
	a := New()
	b := New()
	for i := 1; i <= 100; i++ {
		a.Record(uint64(i))
	}
	for i := 101; i <= 200; i++ {
		b.Record(uint64(i))
	}

	a.Merge(b)
	if a.Count() != 200 {
		t.Errorf("Count after merge = %d, want 200", a.Count())
	}
	if a.Min() != 1 {
		t.Errorf("Min after merge = %d, want 1", a.Min())
	}
	if a.Max() != 200 {
		t.Errorf("Max after merge = %d, want 200", a.Max())
	}
	if a.Sum() != 20100 {
		t.Errorf("Sum after merge = %d, want 20100", a.Sum())
	}
}

func TestHistogramReset(t *testing.T) {
	h := New()
	for i := 0; i < 1000; i++ {
		h.Record(uint64(i + 1))
	}
	h.Reset()
	if h.Count() != 0 {
		t.Errorf("Count after Reset = %d, want 0", h.Count())
	}
	if h.Percentile(99) != 0 {
		t.Errorf("Percentile after Reset = %d, want 0", h.Percentile(99))
	}
}

func TestHistogramConcurrentRecord(t *testing.T) {
	h := New()
	const goroutines = 16
	const samples = 10000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for i := 0; i < samples; i++ {
				h.Record(uint64(r.Intn(1_000_000) + 1))
			}
		}(int64(g))
	}
	wg.Wait()

	if got, want := h.Count(), uint64(goroutines*samples); got != want {
		t.Errorf("concurrent Count() = %d, want %d", got, want)
	}
}

func TestHistogramSnapshotIsolated(t *testing.T) {
	a := New()
	for i := 1; i <= 100; i++ {
		a.Record(uint64(i))
	}
	snap := a.Snapshot()

	for i := 101; i <= 200; i++ {
		a.Record(uint64(i))
	}

	if snap.Count() != 100 {
		t.Errorf("snapshot Count = %d, want 100 (snapshot must not see post-snapshot writes)", snap.Count())
	}
	if a.Count() != 200 {
		t.Errorf("original Count after writes = %d, want 200", a.Count())
	}
}

func BenchmarkHistogramRecord(b *testing.B) {
	h := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Record(uint64(i + 1))
	}
}

func BenchmarkHistogramPercentile(b *testing.B) {
	h := New()
	for i := 1; i <= 100000; i++ {
		h.Record(uint64(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Percentile(99)
	}
}
