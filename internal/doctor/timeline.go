// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
)

// TimelineEvent is one node in the causal timeline: a finding anchored
// to the moment its metric first crossed its threshold.
type TimelineEvent struct {
	FindingRule string
	Signal      string
	FiredAt     time.Time
	Title       string
	Evidence    string
	Severity    Severity
}

// CausalLink connects two TimelineEvents with a confidence score.
type CausalLink struct {
	CauseRule    string
	CauseSignal  string
	EffectRule   string
	EffectSignal string
	Confidence   float64
	GapMs        int64
}

// Timeline is the ordered causal sequence for a diagnostic run.
type Timeline struct {
	ID     string
	Events []TimelineEvent
	Links  []CausalLink
}

type causalRule struct {
	causeSignal  string
	effectSignal string
	maxGap       time.Duration
	baseConf     float64
}

var causalRules = []causalRule{
	// Disk fsync stall → DB write latency
	{"diskio", "syscall", 10 * time.Second, 0.85},
	// DB write latency → upstream API timeout (TCP retransmit surge)
	{"syscall", "tcp", 15 * time.Second, 0.80},
	// Memory pressure imminent → OOM kill
	{"memory", "oom", 120 * time.Second, 0.90},
	{"cgroup_memory", "oom", 120 * time.Second, 0.90},
	// TCP queue saturation → scheduler contention (downstream)
	{"tcp", "sched", 20 * time.Second, 0.75},
	// Disk saturation → scheduler starvation (IO waiters)
	{"diskio", "sched", 20 * time.Second, 0.72},
}

// BuildTimeline constructs the causal timeline from the current findings
// and the engine's signal history.
func BuildTimeline(
	findings []Finding,
	history []*collector.Signals,
	thresholds config.DoctorThresholds,
) *Timeline {
	if len(findings) == 0 {
		return &Timeline{
			Events: []TimelineEvent{},
			Links:  []CausalLink{},
		}
	}

	// 1. Resolve FiredAt for each finding.
	events := make([]TimelineEvent, len(findings))
	for i, f := range findings {
		firedAt := firstFiredAt(f, history)
		events[i] = TimelineEvent{
			FindingRule: f.Rule,
			Signal:      f.Signal,
			FiredAt:     firedAt,
			Title:       f.Title,
			Evidence:    f.Evidence,
			Severity:    f.Severity,
		}
	}

	// Sort events by FiredAt ascending.
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].FiredAt.Equal(events[j].FiredAt) {
			return events[i].FindingRule < events[j].FindingRule
		}
		return events[i].FiredAt.Before(events[j].FiredAt)
	})

	// 2. Build causal links.
	var links []CausalLink
	for i := 0; i < len(events); i++ {
		for j := 0; j < len(events); j++ {
			if i == j {
				continue
			}
			cause := events[i]
			effect := events[j]

			// Cause must precede or equal effect in time.
			if cause.FiredAt.After(effect.FiredAt) {
				continue
			}

			// Look up matching causal rule.
			for _, rule := range causalRules {
				if rule.causeSignal == cause.Signal && rule.effectSignal == effect.Signal {
					gap := effect.FiredAt.Sub(cause.FiredAt)
					if gap <= rule.maxGap {
						conf := rule.baseConf
						if gap > rule.maxGap/2 {
							conf = rule.baseConf * (1.0 - float64(gap)/float64(rule.maxGap))
						}

						if conf >= 0.7 {
							links = append(links, CausalLink{
								CauseRule:    cause.FindingRule,
								CauseSignal:  cause.Signal,
								EffectRule:   effect.FindingRule,
								EffectSignal: effect.Signal,
								Confidence:   conf,
								GapMs:        gap.Milliseconds(),
							})
						}
					}
				}
			}
		}
	}

	// Compute ID
	var hInput strings.Builder
	for _, ev := range events {
		fmt.Fprintf(&hInput, "%s:%s:%d;", ev.FindingRule, ev.Signal, ev.FiredAt.UnixNano())
	}
	for _, l := range links {
		fmt.Fprintf(&hInput, "%s->%s:%f:%d;", l.CauseRule, l.EffectRule, l.Confidence, l.GapMs)
	}
	hash := sha256.Sum256([]byte(hInput.String()))
	id := fmt.Sprintf("%x", hash)[:12]

	return &Timeline{
		ID:     id,
		Events: events,
		Links:  links,
	}
}

// firstFiredAt walks the history ring buffer oldest-first and returns
// the timestamp of the earliest snapshot in which the given finding's
// metric already exceeded its threshold.
//
// Fall back to Finding.FiredAt (current-snapshot timestamp) if history
// is empty or the metric never exceeded the threshold in history.
func firstFiredAt(f Finding, history []*collector.Signals) time.Time {
	for _, s := range history {
		if s == nil {
			continue
		}
		if metricExceeded(s, f.Metric, f.Threshold) {
			return s.Timestamp
		}
	}
	return f.FiredAt
}

// metricExceeded returns true if the specified metric in the signals snapshot
// exceeds or meets the given threshold.
func metricExceeded(s *collector.Signals, metric string, threshold float64) bool {
	switch metric {
	case "disk_sync_p99":
		if s.DiskIO == nil {
			return false
		}
		return float64(s.DiskIO.SyncLatency.P99.Nanoseconds()) >= threshold
	case "disk_write_p99":
		if s.DiskIO == nil {
			return false
		}
		return float64(s.DiskIO.WriteLatency.P99.Nanoseconds()) >= threshold
	case "oom_kills":
		return s.OOM != nil && s.OOM.Count > 0
	case "tcp_retransmit_pct":
		if s.TCP == nil {
			return false
		}
		return s.TCP.RetransmitRate >= threshold
	case "tcp_rtt_p99":
		if s.TCP == nil {
			return false
		}
		return float64(s.TCP.RTT.P99.Nanoseconds()) >= threshold
	case "sched_runq_p99":
		if s.Sched == nil {
			return false
		}
		return float64(s.Sched.RunqDelay.P99.Nanoseconds()) >= threshold
	case "fd_growth_per_sec":
		if s.FD == nil {
			return false
		}
		return s.FD.GrowthRate >= threshold
	case "syscall_p99_max":
		if s.Syscall == nil {
			return false
		}
		for _, entry := range s.Syscall.Entries {
			if bpf.IsBlockingSyscall(entry.SyscallNr) {
				continue
			}
			if float64(entry.Latency.P99.Nanoseconds()) >= threshold {
				return true
			}
		}
		return false
	case "memory_used_pct":
		if s.Memory == nil {
			return false
		}
		return s.Memory.UsedPct >= threshold
	case "syscall_error_pct_max":
		if s.Syscall == nil {
			return false
		}
		for _, entry := range s.Syscall.Entries {
			if bpf.IsBlockingSyscall(entry.SyscallNr) {
				continue
			}
			if entry.Count == 0 {
				continue
			}
			rate := float64(entry.ErrorCount) / float64(entry.Count) * 100.0
			if rate >= threshold {
				return true
			}
		}
		return false
	case "cgroup_memory_used_pct":
		if s.CgroupMemory == nil {
			return false
		}
		for _, c := range s.CgroupMemory.Containers {
			if c.LimitBytes > 0 && c.UsedPct >= threshold {
				return true
			}
		}
		return false
	case "cgroup_memory_high_event_rate":
		if s.CgroupMemory == nil {
			return false
		}
		for _, c := range s.CgroupMemory.Containers {
			if c.HighEventRate >= threshold {
				return true
			}
		}
		return false
	}
	return false
}
