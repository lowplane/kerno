// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"math"
	"testing"
	"time"
)

func TestETADurationPreservesSubSecondPrecision(t *testing.T) {
	eta, ok := etaDuration(0.25)
	if !ok {
		t.Fatal("expected sub-second ETA to be meaningful")
	}
	if eta != 250*time.Millisecond {
		t.Fatalf("expected 250ms, got %s", eta)
	}
}

func TestETADurationRejectsNonMeaningfulValues(t *testing.T) {
	tests := []struct {
		name string
		secs float64
	}{
		{name: "zero", secs: 0},
		{name: "negative", secs: -1},
		{name: "nan", secs: math.NaN()},
		{name: "infinity", secs: math.Inf(1)},
		{name: "beyond ceiling", secs: maxMeaningfulETA.Seconds() + 1},
		{name: "overflow scale", secs: math.MaxFloat64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if eta, ok := etaDuration(tt.secs); ok {
				t.Fatalf("expected ETA to be rejected, got %s", eta)
			}
		})
	}
}

func TestETADurationAcceptsCeiling(t *testing.T) {
	eta, ok := etaDuration(maxMeaningfulETA.Seconds())
	if !ok {
		t.Fatal("expected ceiling ETA to be meaningful")
	}
	if eta != maxMeaningfulETA {
		t.Fatalf("expected %s, got %s", maxMeaningfulETA, eta)
	}
}
