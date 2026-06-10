// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter is a token-bucket rate limiter with probabilistic sampling
// fallback. Once the token bucket empties, Allow() passes events at the
// configured sample rate instead of hard-dropping everything.
// It is safe for concurrent use.
type RateLimiter struct {
	mu         sync.Mutex
	budget     int64
	tokens     int64
	lastRefill time.Time

	sampleRate atomic.Value // holds float64

	dropsTotal   atomic.Int64
	sampledTotal atomic.Int64
}

// NewRateLimiter creates a RateLimiter with the given events/sec budget.
// A budget of 0 disables rate limiting (all events pass).
func NewRateLimiter(budget int64) *RateLimiter {
	rl := &RateLimiter{
		budget:     budget,
		tokens:     budget,
		lastRefill: time.Now(),
	}
	rl.sampleRate.Store(float64(1.0))
	return rl
}

// Allow reports whether the current event should be processed.
// Refills the token bucket proportionally to elapsed time on each call.
// Once exhausted, falls back to probabilistic sampling at SampleRate().
func (rl *RateLimiter) Allow() bool {
	if rl.budget == 0 {
		return true
	}

	rl.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	refill := int64(elapsed * float64(rl.budget))
	if refill > 0 {
		rl.tokens += refill
		if rl.tokens > rl.budget {
			rl.tokens = rl.budget
		}
		rl.lastRefill = now
	}
	if rl.tokens > 0 {
		rl.tokens--
		rl.mu.Unlock()
		return true
	}
	rl.mu.Unlock()

	// Bucket exhausted — fall back to probabilistic sampling.
	sr, ok := rl.sampleRate.Load().(float64)
	if !ok {
		sr = 1.0 // fallback: allow all events
	}
	if sr >= 1.0 || rand.Float64() < sr {
		rl.sampledTotal.Add(1)
		return true
	}
	rl.dropsTotal.Add(1)
	return false
}

// SetSampleRate updates the sampling fraction in [0.0, 1.0].
// 1.0 = pass all events; 0.0 = drop all when bucket is empty.
func (rl *RateLimiter) SetSampleRate(r float64) {
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	rl.sampleRate.Store(r)
}

// SampleRate returns the current sampling fraction.
func (rl *RateLimiter) SampleRate() float64 {
	sr, ok := rl.sampleRate.Load().(float64)
	if !ok {
		return 1.0 // fallback value
	}
	return sr
}

// DropsTotal returns the cumulative events dropped by the sampler.
func (rl *RateLimiter) DropsTotal() int64 { return rl.dropsTotal.Load() }

// SampledTotal returns cumulative events passed via sampling
// (after the token bucket was exhausted).
func (rl *RateLimiter) SampledTotal() int64 { return rl.sampledTotal.Load() }
