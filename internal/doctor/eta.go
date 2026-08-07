// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"math"
	"time"
)

const maxMeaningfulETA = 7 * 24 * time.Hour

// etaDuration converts seconds to a duration without truncating useful
// sub-second precision and rejects values too large to be actionable.
func etaDuration(etaSecs float64) (time.Duration, bool) {
	if etaSecs <= 0 || math.IsNaN(etaSecs) || math.IsInf(etaSecs, 0) {
		return 0, false
	}

	eta := time.Duration(etaSecs * float64(time.Second))
	if eta <= 0 || eta > maxMeaningfulETA {
		return 0, false
	}

	return eta, true
}

// fdHeadroom returns (remaining, limit, exact) where remaining is the number
// of file descriptors before the process hits its limit, limit is the value
// used as the ceiling, and exact is true when remaining was derived from a
// live /proc read rather than a window delta.
//
// Priority order:
//  1. entry.CurrentFDs + entry.FDLimit  — both available: most accurate
//  2. entry.CurrentFDs + default limit  — live count, assumed limit
//  3. entry.NetDelta   + entry.FDLimit  — window delta, known limit (rare)
//  4. entry.NetDelta   + default limit  — worst case: window delta only
//
// If remaining <= 0, returns (1, limit, exact) so callers don't divide by zero.
func fdHeadroom(currentFDs, netDelta int64, fdLimit int) (remaining float64, limit float64, exact bool) {
	const defaultLimit = 65536.0
	limit = defaultLimit
	if fdLimit > 0 {
		limit = float64(fdLimit)
	}
	if currentFDs > 0 {
		remaining = limit - float64(currentFDs)
		exact = true
	} else {
		remaining = limit - float64(netDelta)
		exact = false
	}
	if remaining <= 0 {
		remaining = 1
	}
	return
}
