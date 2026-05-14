// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

// Package aggregator provides bounded-memory aggregation primitives
// (histograms, LRU maps) used by signal collectors to compute
// percentiles and per-key statistics over a window.
package aggregator

import (
	"math"
	"math/bits"
	"sync"
)

// histBuckets covers values in [1, 2^64). Each bucket i holds the count
// of values falling into [2^i, 2^(i+1)).
const histBuckets = 64

// Histogram is a log2-bucketed histogram for non-negative integer values
// (typically nanosecond latencies). It provides O(1) insertion and
// O(64) percentile estimation with bounded memory (~512 bytes regardless
// of how many values are recorded).
//
// Bucket precision is one power of two. For latency reporting (p50/p95/p99
// at sub-microsecond to multi-second range) this maps to ~50% relative
// error on the bucket midpoint estimate — fine for the ranking and
// thresholding the doctor engine performs.
type Histogram struct {
	mu      sync.Mutex
	buckets [histBuckets]uint64
	count   uint64
	sum     uint64
	minV    uint64 // 0 when no values recorded
	maxV    uint64
}

// New creates an empty histogram.
func New() *Histogram { return &Histogram{} }

// Record adds a value to the histogram. Zero is treated as 1 (since
// log2(0) is undefined and zero-valued samples carry no useful
// distribution signal).
func (h *Histogram) Record(v uint64) {
	if v == 0 {
		v = 1
	}
	bucket := bits.Len64(v) - 1
	if bucket < 0 {
		bucket = 0
	}
	if bucket >= histBuckets {
		bucket = histBuckets - 1
	}
	h.mu.Lock()
	h.buckets[bucket]++
	h.count++
	h.sum += v
	if v > h.maxV {
		h.maxV = v
	}
	if h.minV == 0 || v < h.minV {
		h.minV = v
	}
	h.mu.Unlock()
}

// Count returns the total number of recorded values.
func (h *Histogram) Count() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// Sum returns the sum of all recorded values.
func (h *Histogram) Sum() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sum
}

// Mean returns the average value. Returns 0 if no values were recorded.
func (h *Histogram) Mean() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return 0
	}
	return float64(h.sum) / float64(h.count)
}

// Max returns the largest recorded value.
func (h *Histogram) Max() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.maxV
}

// Min returns the smallest recorded value (0 when no values).
func (h *Histogram) Min() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.minV
}

// Percentile returns the estimated value at the p-th percentile (0–100).
// The estimate is the midpoint of the bucket whose cumulative count
// crosses the target, clamped to the observed [Min, Max] range so the
// estimate never lies outside the data.
func (h *Histogram) Percentile(p float64) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return 0
	}
	if p <= 0 {
		return h.minV
	}
	if p >= 100 {
		return h.maxV
	}

	target := uint64(math.Ceil(float64(h.count) * p / 100.0))
	if target == 0 {
		target = 1
	}

	var cum uint64
	for i := range &h.buckets {
		cum += h.buckets[i]
		if cum >= target {
			return h.bucketEstimate(i)
		}
	}
	return h.maxV
}

// bucketEstimate returns the midpoint of bucket i, clamped to the
// observed [min, max] range. Caller must hold h.mu.
//
// i is bounded by the loop in Percentile to [0, histBuckets), so the
// shift by uint(i) cannot overflow.
func (h *Histogram) bucketEstimate(i int) uint64 {
	if i < 0 || i >= histBuckets-1 {
		return h.maxV
	}
	low := uint64(1) << uint(i) //nolint:gosec // i is bounded by histBuckets (64)
	high := low << 1
	mid := low + (high-low)/2
	if mid < h.minV {
		return h.minV
	}
	if mid > h.maxV {
		return h.maxV
	}
	return mid
}

// Reset clears all recorded data.
func (h *Histogram) Reset() {
	h.mu.Lock()
	h.buckets = [histBuckets]uint64{}
	h.count = 0
	h.sum = 0
	h.minV = 0
	h.maxV = 0
	h.mu.Unlock()
}

// Merge folds the contents of other into h. After merging, percentiles
// computed on h reflect the union of samples.
func (h *Histogram) Merge(other *Histogram) {
	other.mu.Lock()
	otherBuckets := other.buckets
	otherCount := other.count
	otherSum := other.sum
	otherMin := other.minV
	otherMax := other.maxV
	other.mu.Unlock()

	h.mu.Lock()
	for i := range otherBuckets {
		h.buckets[i] += otherBuckets[i]
	}
	h.count += otherCount
	h.sum += otherSum
	if otherMax > h.maxV {
		h.maxV = otherMax
	}
	if h.minV == 0 || (otherMin != 0 && otherMin < h.minV) {
		h.minV = otherMin
	}
	h.mu.Unlock()
}

// Snapshot returns a copy of the histogram safe for concurrent reads.
// The original is unaffected.
func (h *Histogram) Snapshot() *Histogram {
	out := New()
	out.Merge(h)
	return out
}
