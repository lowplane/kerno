// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/collector"
)

func TestPredictFDExhaustionPreservesSubSecondETA(t *testing.T) {
	now := time.Now()
	snapshots := []*collector.Signals{
		{
			Timestamp: now,
			FD: &collector.FDSnapshot{
				GrowthRate: 4,
				NetDelta:   65535,
			},
		},
		{
			Timestamp: now.Add(time.Second),
			FD: &collector.FDSnapshot{
				GrowthRate: 4,
				NetDelta:   65535,
			},
		},
	}

	predictions := predictFDExhaustion(snapshots)
	if len(predictions) != 1 {
		t.Fatalf("expected one FD exhaustion prediction, got %d", len(predictions))
	}
	if predictions[0].TimeToImpact != 250*time.Millisecond {
		t.Fatalf("expected 250ms ETA, got %s", predictions[0].TimeToImpact)
	}
}

func TestPredictFDExhaustionRejectsUnmeaningfulETA(t *testing.T) {
	now := time.Now()
	snapshots := []*collector.Signals{
		{
			Timestamp: now,
			FD: &collector.FDSnapshot{
				GrowthRate: 0.01,
			},
		},
		{
			Timestamp: now.Add(time.Second),
			FD: &collector.FDSnapshot{
				GrowthRate: 0.01,
			},
		},
	}

	predictions := predictFDExhaustion(snapshots)
	if len(predictions) != 0 {
		t.Fatalf("expected no prediction for ETA beyond meaningful window, got %d", len(predictions))
	}
}
