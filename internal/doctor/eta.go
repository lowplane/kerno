// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"math"
	"time"
)

const maxMeaningfulETA = 7 * 24 * time.Hour

func etaFromSeconds(seconds float64) (time.Duration, bool) {
	if seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, false
	}
	if seconds > maxMeaningfulETA.Seconds() {
		return 0, false
	}

	return time.Duration(seconds * float64(time.Second)), true
}
