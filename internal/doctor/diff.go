// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"time"
)

// FindingStatus represents the state of a finding in the current watch cycle.
type FindingStatus int

const (
	StatusNew FindingStatus = iota
	StatusOngoing
	StatusResolved
)

// DiffedFinding wraps a Finding with status and timing for the watch UI.
type DiffedFinding struct {
	Finding    Finding
	Status     FindingStatus
	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt time.Time
}

// Diff compares the current findings against the previous state and returns
// the updated set of findings to display.
//
// Rules:
// 1. If finding exists in curr but not in prev, it is StatusNew.
// 2. If finding exists in both, it is StatusOngoing.
// 3. If finding exists in prev but not in curr, it is StatusResolved.
// 4. StatusResolved findings are kept for keepResolvedDuration (e.g. 30s)
//    before being dropped.
func Diff(prev []DiffedFinding, curr []Finding, keepResolvedDuration time.Duration) []DiffedFinding {
	now := time.Now()
	currMap := make(map[string]Finding)
	for _, f := range curr {
		currMap[f.Fingerprint()] = f
	}

	prevMap := make(map[string]DiffedFinding)
	for _, df := range prev {
		prevMap[df.Finding.Fingerprint()] = df
	}

	var result []DiffedFinding

	// Process current findings.
	for _, f := range curr {
		fingerprint := f.Fingerprint()
		if pf, ok := prevMap[fingerprint]; ok {
			// Ongoing finding.
			result = append(result, DiffedFinding{
				Finding:    f,
				Status:     StatusOngoing,
				FirstSeen:  pf.FirstSeen,
				LastSeen:   now,
				ResolvedAt: time.Time{},
			})
		} else {
			// New finding.
			result = append(result, DiffedFinding{
				Finding:    f,
				Status:     StatusNew,
				FirstSeen:  now,
				LastSeen:   now,
				ResolvedAt: time.Time{},
			})
		}
	}

	// Process resolved findings (those in prev but not in curr).
	for _, df := range prev {
		fingerprint := df.Finding.Fingerprint()
		if _, ok := currMap[fingerprint]; !ok {
			// Finding is missing in current cycle.
			if df.Status != StatusResolved {
				// Just resolved.
				df.Status = StatusResolved
				df.ResolvedAt = now
			}

			// Keep if not expired.
			if now.Sub(df.ResolvedAt) < keepResolvedDuration {
				result = append(result, df)
			}
		}
	}

	return result
}
