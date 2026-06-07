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
