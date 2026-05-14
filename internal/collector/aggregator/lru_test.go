// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"sync"
	"testing"
)

func TestLRUPutGet(t *testing.T) {
	l := NewLRU[string, int](3)
	l.Put("a", 1)
	l.Put("b", 2)
	l.Put("c", 3)

	if v, ok := l.Get("a"); !ok || v != 1 {
		t.Errorf("Get('a') = (%d, %v), want (1, true)", v, ok)
	}
	if v, ok := l.Get("b"); !ok || v != 2 {
		t.Errorf("Get('b') = (%d, %v), want (2, true)", v, ok)
	}
}

func TestLRUEviction(t *testing.T) {
	l := NewLRU[string, int](2)
	l.Put("a", 1)
	l.Put("b", 2)
	l.Put("c", 3) // should evict "a" (least recently used)

	if _, ok := l.Get("a"); ok {
		t.Error("Get('a') should miss after eviction")
	}
	if _, ok := l.Get("b"); !ok {
		t.Error("Get('b') should still hit")
	}
	if _, ok := l.Get("c"); !ok {
		t.Error("Get('c') should hit")
	}
	if got := l.Evicted(); got != 1 {
		t.Errorf("Evicted() = %d, want 1", got)
	}
}

func TestLRUMoveToFrontOnGet(t *testing.T) {
	l := NewLRU[string, int](2)
	l.Put("a", 1)
	l.Put("b", 2)

	// Touch "a" so it becomes most recently used.
	if _, ok := l.Get("a"); !ok {
		t.Fatal("Get('a') should hit")
	}

	// Insert "c": "b" should evict, not "a".
	l.Put("c", 3)

	if _, ok := l.Get("a"); !ok {
		t.Error("'a' should still be present after Get refreshed it")
	}
	if _, ok := l.Get("b"); ok {
		t.Error("'b' should have been evicted")
	}
}

func TestLRUUpdateExisting(t *testing.T) {
	l := NewLRU[string, int](2)
	l.Put("a", 1)
	l.Put("a", 99) // update, not insert

	if v, _ := l.Get("a"); v != 99 {
		t.Errorf("Get('a') = %d, want 99", v)
	}
	if l.Len() != 1 {
		t.Errorf("Len() = %d, want 1", l.Len())
	}
	if l.Evicted() != 0 {
		t.Errorf("Evicted() = %d, want 0 (update, not eviction)", l.Evicted())
	}
}

func TestLRURange(t *testing.T) {
	l := NewLRU[string, int](5)
	l.Put("a", 1)
	l.Put("b", 2)
	l.Put("c", 3)

	var keys []string
	l.Range(func(k string, _ int) bool {
		keys = append(keys, k)
		return true
	})

	// Newest-first order: c, b, a
	want := []string{"c", "b", "a"}
	if len(keys) != len(want) {
		t.Fatalf("Range visited %d keys, want %d", len(keys), len(want))
	}
	for i, k := range keys {
		if k != want[i] {
			t.Errorf("Range[%d] = %q, want %q", i, k, want[i])
		}
	}
}

func TestLRURangeEarlyExit(t *testing.T) {
	l := NewLRU[string, int](5)
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		l.Put(k, 0)
	}

	count := 0
	l.Range(func(string, int) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Errorf("Range visited %d, want 2 (early exit)", count)
	}
}

func TestLRUConcurrent(t *testing.T) {
	l := NewLRU[int, int](100)
	var wg sync.WaitGroup
	const writers = 8
	const ops = 5000

	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(off int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				k := off*ops + i
				l.Put(k, k)
				l.Get(k)
			}
		}(w)
	}
	wg.Wait()

	if l.Len() > 100 {
		t.Errorf("Len() = %d, exceeds cap of 100", l.Len())
	}
}

func TestLRUZeroCapacityCoercedToOne(t *testing.T) {
	l := NewLRU[string, int](0)
	if l.Cap() != 1 {
		t.Errorf("Cap() = %d, want 1 (zero cap should coerce to 1)", l.Cap())
	}
	l.Put("a", 1)
	l.Put("b", 2) // evicts "a"

	if _, ok := l.Get("a"); ok {
		t.Error("'a' should have been evicted")
	}
	if v, _ := l.Get("b"); v != 2 {
		t.Errorf("Get('b') = %d, want 2", v)
	}
}
