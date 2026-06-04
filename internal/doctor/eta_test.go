// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"math"
	"testing"
	"time"
)

func TestETAFromSecondsPreservesSubSecondPrecision(t *testing.T) {
	eta, ok := etaFromSeconds(0.25)
	if !ok {
		t.Fatal("expected 250ms ETA to be meaningful")
	}
	if eta != 250*time.Millisecond {
		t.Fatalf("expected 250ms ETA, got %s", eta)
	}
}

func TestETAFromSecondsRejectsUnmeaningfulValues(t *testing.T) {
	tests := []float64{
		0,
		-1,
		math.NaN(),
		math.Inf(1),
		maxMeaningfulETA.Seconds() + 1,
	}

	for _, seconds := range tests {
		if eta, ok := etaFromSeconds(seconds); ok {
			t.Fatalf("expected %v seconds to be rejected, got ETA %s", seconds, eta)
		}
	}
}
