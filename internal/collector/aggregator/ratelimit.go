// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

var (
	rngMu sync.Mutex
	rng   = func() *mathrand.Rand { //nolint:gosec // G404: seeded from crypto/rand, used only for sampling
		var seed [16]byte
		if _, err := rand.Read(seed[:]); err != nil {
			panic("crypto/rand unavailable: " + err.Error())
		}
		s1 := binary.LittleEndian.Uint64(seed[:8])
		s2 := binary.LittleEndian.Uint64(seed[8:])
		return mathrand.New(mathrand.NewPCG(s1, s2)) // #nosec G404
	}()
)

func randFloat64() float64 {
	rngMu.Lock()
	v := rng.Float64()
	rngMu.Unlock()
	return v
}

type RateLimiter struct {
	mu         sync.Mutex
	budget     int64
	tokens     int64
	lastRefill time.Time

	sampleRate atomic.Value

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

	sr, ok := rl.sampleRate.Load().(float64)
	if !ok {
		sr = 1.0
	}
	if sr >= 1.0 || randFloat64() < sr {
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
	sr, ok := rl.sampleRate.Load().(float64)
	if !ok {
		return 1.0
	}
	return sr
}

func (rl *RateLimiter) DropsTotal() int64 { return rl.dropsTotal.Load() }

func (rl *RateLimiter) SampledTotal() int64 { return rl.sampledTotal.Load() }
