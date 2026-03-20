// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"sync"
	"time"

	"github.com/lowplane/kerno/internal/doctor"
)

// Cache provides TTL-based caching for AI analysis responses.
// Keyed by findings fingerprint (rule names + severities), not exact values,
// so similar diagnostic situations share cache entries.
// This prevents redundant LLM calls in continuous mode.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	response  *doctor.AnalysisResponse
	expiresAt time.Time
}

// NewCache creates a new TTL cache.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

// Get returns a cached response if it exists and hasn't expired.
func (c *Cache) Get(key string) (*doctor.AnalysisResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.response, true
}

// Set stores a response in the cache.
func (c *Cache) Set(key string, response *doctor.AnalysisResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		response:  response,
		expiresAt: time.Now().Add(c.ttl),
	}

	// Lazy eviction: clean expired entries if cache is growing.
	if len(c.entries) > 100 {
		c.evictExpiredLocked()
	}
}

func (c *Cache) evictExpiredLocked() {
	now := time.Now()
	for k, v := range c.entries {
		if now.After(v.expiresAt) {
			delete(c.entries, k)
		}
	}
}
