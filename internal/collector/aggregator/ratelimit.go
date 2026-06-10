// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

type RateLimiter struct {
	mu         sync.Mutex
	budget     int64
	tokens     int64
	lastRefill time.Time

	sampleRate atomic.Value // holds float64

	dropsTotal   atomic.Int64
	sampledTotal atomic.Int64
}

func NewRateLimiter(budget int64) *RateLimiter {
	rl := &RateLimiter{
		budget:     budget,
		tokens:     budget,
		lastRefill: time.Now(),
	}
	rl.sampleRate.Store(float64(1.0))
	return rl
}

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

	sr := rl.sampleRate.Load().(float64)
	if sr >= 1.0 || rand.Float64() < sr {
		rl.sampledTotal.Add(1)
		return true
	}
	rl.dropsTotal.Add(1)
	return false
}

func (rl *RateLimiter) SetSampleRate(r float64) {
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	rl.sampleRate.Store(r)
}

func (rl *RateLimiter) SampleRate() float64 {
	return rl.sampleRate.Load().(float64)
}

func (rl *RateLimiter) DropsTotal() int64 { return rl.dropsTotal.Load() }

func (rl *RateLimiter) SampledTotal() int64 { return rl.sampledTotal.Load() }
