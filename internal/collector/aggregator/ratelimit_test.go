// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"sort"
	"testing"
	"time"
)

func TestRateLimiter_UnlimitedBudget(t *testing.T) {
	rl := NewRateLimiter(0)
	for i := 0; i < 10_000; i++ {
		if !rl.Allow() {
			t.Fatal("unlimited budget: expected Allow()=true")
		}
	}
}

func TestRateLimiter_DropsWhenBucketExhausted(t *testing.T) {
	rl := NewRateLimiter(5)
	rl.SetSampleRate(0.0)

	var passed, dropped int
	for i := 0; i < 1000; i++ {
		if rl.Allow() {
			passed++
		} else {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("expected drops > 0 when bucket exhausted and sample rate = 0")
	}
	if rl.DropsTotal() == 0 {
		t.Fatal("DropsTotal() should be non-zero")
	}
	t.Logf("passed=%d dropped=%d", passed, dropped)
}

func TestRateLimiter_SamplingRatio(t *testing.T) {
	rl := NewRateLimiter(1)
	rl.SetSampleRate(0.2)
	time.Sleep(5 * time.Millisecond)

	const total = 100_000
	passed := 0
	for i := 0; i < total; i++ {
		if rl.Allow() {
			passed++
		}
	}
	ratio := float64(passed) / total
	if ratio < 0.15 || ratio > 0.30 {
		t.Fatalf("expected pass ratio ~0.20, got %.3f", ratio)
	}
	t.Logf("sampling ratio=%.3f", ratio)
}

func TestRateLimiter_HistogramPercentileAccuracy(t *testing.T) {
	rl := NewRateLimiter(1)
	rl.SetSampleRate(0.8)
	time.Sleep(5 * time.Millisecond)

	const n = 50_000
	groundTruthP99 := int(float64(n) * 0.99)

	var kept []int
	for v := 0; v < n; v++ {
		if rl.Allow() {
			kept = append(kept, v)
		}
	}
	sort.Ints(kept)

	sampledP99 := kept[int(float64(len(kept))*0.99)]
	diff := sampledP99 - groundTruthP99
	if diff < 0 {
		diff = -diff
	}
	pctErr := float64(diff) / float64(groundTruthP99)
	if pctErr > 0.05 {
		t.Fatalf("p99 error %.2f%% exceeds 5%% limit (groundTruth=%d sampled=%d)",
			pctErr*100, groundTruthP99, sampledP99)
	}
	t.Logf("p99 groundTruth=%d sampled=%d error=%.2f%%",
		groundTruthP99, sampledP99, pctErr*100)
}
