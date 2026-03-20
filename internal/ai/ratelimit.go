// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RateLimitedProvider wraps a Provider with a token bucket rate limiter.
// Prevents excessive LLM calls in continuous mode.
type RateLimitedProvider struct {
	inner Provider

	mu        sync.Mutex
	tokens    int
	maxTokens int
	interval  time.Duration
	lastFill  time.Time
}

// NewRateLimitedProvider wraps a provider with rate limiting.
// perMinute is the maximum number of calls allowed per minute.
func NewRateLimitedProvider(inner Provider, perMinute int) *RateLimitedProvider {
	if perMinute <= 0 {
		perMinute = 10
	}
	return &RateLimitedProvider{
		inner:     inner,
		tokens:    perMinute,
		maxTokens: perMinute,
		interval:  time.Minute,
		lastFill:  time.Now(),
	}
}

func (r *RateLimitedProvider) Name() string {
	return r.inner.Name()
}

func (r *RateLimitedProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if !r.allow() {
		return nil, fmt.Errorf("AI rate limit exceeded (%d calls/min)", r.maxTokens)
	}
	return r.inner.Complete(ctx, req)
}

func (r *RateLimitedProvider) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastFill)

	// Refill tokens based on elapsed time.
	if elapsed >= r.interval {
		r.tokens = r.maxTokens
		r.lastFill = now
	} else {
		// Proportional refill.
		refill := int(float64(r.maxTokens) * (float64(elapsed) / float64(r.interval)))
		if refill > 0 {
			r.tokens += refill
			if r.tokens > r.maxTokens {
				r.tokens = r.maxTokens
			}
			r.lastFill = now
		}
	}

	if r.tokens <= 0 {
		return false
	}

	r.tokens--
	return true
}
