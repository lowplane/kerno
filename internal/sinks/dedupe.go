package sinks

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/optiqor/kerno/internal/doctor"
	"github.com/optiqor/kerno/internal/metrics"
)

// Deduper filters out repeated findings to prevent alert fatigue.
type Deduper struct {
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]time.Time
}

// NewDeduper creates a new Deduper with the given time-to-live.
func NewDeduper(ttl time.Duration) *Deduper {
	return &Deduper{
		ttl:   ttl,
		cache: make(map[string]time.Time),
	}
}

// Filter returns only the findings that are novel (not seen within TTL).
// It increments the deduplication metric for any dropped findings.
func (d *Deduper) Filter(findings []doctor.Finding) []doctor.Finding {
	if d.ttl <= 0 || len(findings) == 0 {
		return findings
	}

	now := time.Now()
	novel := make([]doctor.Finding, 0, len(findings))

	d.mu.Lock()
	defer d.mu.Unlock()

	// Clean up stale entries on every filter to prevent unbounded memory growth.
	// In a high-throughput system, this would be a background goroutine, but
	// kerno doctor runs relatively infrequently.
	for k, v := range d.cache {
		if now.Sub(v) > d.ttl {
			delete(d.cache, k)
		}
	}

	for _, f := range findings {
		key := fingerprint(f)
		if lastSeen, exists := d.cache[key]; exists && now.Sub(lastSeen) <= d.ttl {
			metrics.SinksDedupedTotal.WithLabelValues("all").Inc()
			continue
		}
		d.cache[key] = now
		novel = append(novel, f)
	}

	return novel
}

// fingerprint creates a unique key for deduplication.
func fingerprint(f doctor.Finding) string {
	// Include Rule, Severity, and Process.
	h := sha256.New()
	fmt.Fprintf(h, "%s:%d:%s", f.Rule, f.Severity, f.Process)
	return fmt.Sprintf("%x", h.Sum(nil))
}
