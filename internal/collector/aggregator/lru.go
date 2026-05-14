// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"container/list"
	"sync"
)

// LRU is a fixed-capacity, thread-safe LRU map. It is used by collectors
// to cap per-key aggregation memory (e.g., per-(syscall, comm) histograms)
// while preferentially keeping the most recently seen keys.
//
// When inserting beyond the capacity, the least recently used entry is
// evicted. Eviction count is exposed so collectors can self-monitor.
type LRU[K comparable, V any] struct {
	mu      sync.Mutex
	cap     int
	list    *list.List // front is newest
	items   map[K]*list.Element
	evicted uint64
}

type lruEntry[K comparable, V any] struct {
	k K
	v V
}

// NewLRU creates an LRU with the given capacity. capacity <= 0 is
// treated as 1 (a degenerate case where every Put evicts).
func NewLRU[K comparable, V any](capacity int) *LRU[K, V] {
	if capacity <= 0 {
		capacity = 1
	}
	return &LRU[K, V]{
		cap:   capacity,
		list:  list.New(),
		items: make(map[K]*list.Element, capacity),
	}
}

// Get returns the value for k, marking it as recently used. The second
// return value is false if k is not present.
func (l *LRU[K, V]) Get(k K) (V, bool) {
	var zero V
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.items[k]
	if !ok {
		return zero, false
	}
	l.list.MoveToFront(el)
	entry, _ := el.Value.(*lruEntry[K, V])
	return entry.v, true
}

// Put inserts or updates a key. If the cache is at capacity and the key
// is new, the LRU entry is evicted. The eviction count is incremented
// (see Evicted) so callers can detect cardinality pressure.
func (l *LRU[K, V]) Put(k K, v V) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if el, ok := l.items[k]; ok {
		l.list.MoveToFront(el)
		entry, _ := el.Value.(*lruEntry[K, V])
		entry.v = v
		return
	}

	if l.list.Len() >= l.cap {
		oldest := l.list.Back()
		if oldest != nil {
			entry, _ := oldest.Value.(*lruEntry[K, V])
			l.list.Remove(oldest)
			delete(l.items, entry.k)
			l.evicted++
		}
	}

	entry := &lruEntry[K, V]{k: k, v: v}
	el := l.list.PushFront(entry)
	l.items[k] = el
}

// Len returns the current number of entries.
func (l *LRU[K, V]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.list.Len()
}

// Cap returns the configured capacity.
func (l *LRU[K, V]) Cap() int { return l.cap }

// Evicted returns the cumulative number of evictions since the LRU was
// created. Useful as a self-monitoring signal: non-zero evictions mean
// the workload exceeds the configured capacity.
func (l *LRU[K, V]) Evicted() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.evicted
}

// Range iterates all entries newest-first. Returning false from fn stops
// iteration. The visit order is stable for the duration of the call but
// the LRU is locked, so callers should keep fn cheap.
func (l *LRU[K, V]) Range(fn func(k K, v V) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for el := l.list.Front(); el != nil; el = el.Next() {
		entry, _ := el.Value.(*lruEntry[K, V])
		if !fn(entry.k, entry.v) {
			return
		}
	}
}
