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

func TestFDHeadroom(t *testing.T) {
	tests := []struct {
		name           string
		currentFDs     int64
		netDelta       int64
		fdLimit        int
		expectedRemain float64
		expectedLimit  float64
		expectedExact  bool
	}{
		{
			name:           "Case 1: Both currentFDs and fdLimit set",
			currentFDs:     64000,
			netDelta:       100,
			fdLimit:        70000,
			expectedRemain: 6000,
			expectedLimit:  70000,
			expectedExact:  true,
		},
		{
			name:           "Case 2: currentFDs set, fdLimit = 0 (defaults to 65536)",
			currentFDs:     64000,
			netDelta:       100,
			fdLimit:        0,
			expectedRemain: 1536,
			expectedLimit:  65536,
			expectedExact:  true,
		},
		{
			name:           "Case 3: currentFDs = 0, fdLimit set (falls back to netDelta with known limit)",
			currentFDs:     0,
			netDelta:       500,
			fdLimit:        80000,
			expectedRemain: 79500,
			expectedLimit:  80000,
			expectedExact:  false,
		},
		{
			name:           "Case 4: Neither set (falls back to netDelta with 65536 default limit)",
			currentFDs:     0,
			netDelta:       500,
			fdLimit:        0,
			expectedRemain: 65036,
			expectedLimit:  65536,
			expectedExact:  false,
		},
		{
			name:           "Case 5: remaining <= 0 (returns remaining = 1)",
			currentFDs:     66000,
			netDelta:       100,
			fdLimit:        65536,
			expectedRemain: 1,
			expectedLimit:  65536,
			expectedExact:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remain, limit, exact := fdHeadroom(tt.currentFDs, tt.netDelta, tt.fdLimit)
			if remain != tt.expectedRemain {
				t.Errorf("expected remaining=%v, got %v", tt.expectedRemain, remain)
			}
			if limit != tt.expectedLimit {
				t.Errorf("expected limit=%v, got %v", tt.expectedLimit, limit)
			}
			if exact != tt.expectedExact {
				t.Errorf("expected exact=%v, got %v", tt.expectedExact, exact)
			}
		})
	}
}
