// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"math/rand"
	"sync"
	"testing"
)

func TestHistogramTableDriven(t *testing.T) {
	// 1. Defining a comprehensive, boundary-focused table structure
	tests := []struct {
		name      string
		values    []uint64
		wantCount uint64
		wantSum   uint64
		wantMin   uint64
		wantMax   uint64
		wantP50   uint64
		wantP95   uint64
		wantP99   uint64
		wantP100  uint64
		wantP0    uint64
	}{
		// --- BOUNDARY COVERAGE REQUESTS ---
		{
			name:      "zero / empty inputs",
			values:    []uint64{},
			wantCount: 0,
			wantSum:   0,
			wantMin:   0,
			wantMax:   0,
			wantP50:   0,
			wantP99:   0,
		},
		{
			name:      "single value allocation",
			values:    []uint64{10},
			wantCount: 1,
			wantSum:   10,
			wantMin:   10,
			wantMax:   10,
			wantP50:   10,
			wantP99:   10,
		},
		{
			name:      "exact log2 bucket edge",
			values:    []uint64{1024}, // 2^10 edge boundary
			wantCount: 1,
			wantSum:   1024,
			wantMin:   1024,
			wantMax:   1024,
			wantP50:   1024,
			wantP99:   1024,
		},
		{
			name:      "one past the bucket edge",
			values:    []uint64{1025}, // 2^10 + 1 boundary
			wantCount: 1,
			wantSum:   1025,
			wantMin:   1025,
			wantMax:   1025,
			wantP50:   1025,
			wantP99:   1025,
		},
		{
			name:      "max bucket clamping at bucket 63",
			values:    []uint64{18446744073709551615}, // Max uint64 value to force bucket 63 clamp
			wantCount: 1,
			wantSum:   18446744073709551615,
			wantMin:   18446744073709551615,
			wantMax:   18446744073709551615,
			wantP50:   18446744073709551615,
			wantP99:   18446744073709551615,
		},

		// --- ORIGINAL TESTING CASES (RETING RETAINED TO PREVENT REGRESSION) ---
		{
			name:      "original static record sample",
			values:    []uint64{100, 200, 300, 400, 500},
			wantCount: 5,
			wantSum:   1500,
			wantMin:   100,
			wantMax:   500,
		},
		{
			name:     "original clamp matching min max",
			values:   []uint64{50_000_000, 60_000_000, 70_000_000},
			wantP0:   50_000_000, // original checked p0 == Min
			wantP100: 70_000_000, // original checked p100 == Max
		},
	}

	// 2. Iterating through tests dynamically using t.Run and t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := New()
			for _, v := range tt.values {
				h.Record(v)
			}

			// Validate explicit dynamic math metrics if they are set in our table setup
			if tt.wantCount != 0 || len(tt.values) == 0 {
				if got := h.Count(); got != tt.wantCount {
					t.Errorf("Count() = %d, want %d", got, tt.wantCount)
				}
			}
			if tt.wantSum != 0 {
				if got := h.Sum(); got != tt.wantSum {
					t.Errorf("Sum() = %d, want %d", got, tt.wantSum)
				}
			}
			if tt.wantMin != 0 {
				if got := h.Min(); got != tt.wantMin {
					t.Errorf("Min() = %d, want %d", got, tt.wantMin)
				}
			}
			if tt.wantMax != 0 {
				if got := h.Max(); got != tt.wantMax {
					t.Errorf("Max() = %d, want %d", got, tt.wantMax)
				}
			}
			if tt.wantP50 != 0 {
				if got := h.Percentile(50); got != tt.wantP50 {
					t.Errorf("Percentile(50) = %d, want %d", got, tt.wantP50)
				}
			}
			if tt.wantP99 != 0 {
				if got := h.Percentile(99); got != tt.wantP99 {
					t.Errorf("Percentile(99) = %d, want %d", got, tt.wantP99)
				}
			}
			if tt.wantP100 != 0 {
				if got := h.Percentile(100); got != tt.wantP100 {
					t.Errorf("Percentile(100) = %d, want %d", got, tt.wantP100)
				}
			}
			if tt.wantP0 != 0 {
				if got := h.Percentile(0); got != tt.wantP0 {
					t.Errorf("Percentile(0) = %d, want %d", got, tt.wantP0)
				}
			}
		})
	}
}

// --- SEQUENTIAL PROPERTY & FUNCTIONAL RUNS ---

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
	h := New()
	for i := 1024; i < 2048; i++ {
		h.Record(uint64(i))
	}
	p99 := h.Percentile(99)
	if p99 < 1024 || p99 >= 2048 {
		t.Errorf("p99 = %d, want in [1024, 2048)", p99)
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

// --- SYSTEM BENCHMARKS ---

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
