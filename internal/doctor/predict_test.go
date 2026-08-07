// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/collector"
)

func TestPredict_FDExhaustion(t *testing.T) {
	now := time.Now()

	t.Run("Accurate", func(t *testing.T) {
		snapshots := []*collector.Signals{
			{
				Timestamp: now,
				FD: &collector.FDSnapshot{
					GrowthRate: 10.0,
				},
			},
			{
				Timestamp: now.Add(10 * time.Second),
				FD: &collector.FDSnapshot{
					GrowthRate: 10.0,
					Entries: []collector.FDEntry{
						{PID: 1234, Comm: "leak-proc", GrowthRate: 10.0, NetDelta: 100, CurrentFDs: 64000, FDLimit: 65536},
					},
				},
			},
		}

		report := Predict(snapshots)
		var fdPred *Prediction
		for i := range report.Predictions {
			if report.Predictions[i].Signal == "fd" {
				fdPred = &report.Predictions[i]
				break
			}
		}

		if fdPred == nil {
			t.Fatal("expected fd prediction, got none")
		}

		// limit is 65536. currentFDs is 64000. remaining is 1536.
		// avgRate is 10.0. etaSecs is 153.6.
		expectedETA := 153600 * time.Millisecond // 153.6s
		if fdPred.TimeToImpact != expectedETA {
			t.Errorf("expected TimeToImpact to be %v, got %v", expectedETA, fdPred.TimeToImpact)
		}

		if fdPred.Limit != "ulimit 65536" {
			t.Errorf("expected Limit to be 'ulimit 65536', got %q", fdPred.Limit)
		}

		if !strings.Contains(fdPred.CurrentValue, "64000 open fds") {
			t.Errorf("expected CurrentValue to contain '64000 open fds', got %q", fdPred.CurrentValue)
		}

		if strings.Contains(fdPred.CurrentValue, "live count unavailable") {
			t.Errorf("expected CurrentValue to not contain 'live count unavailable', got %q", fdPred.CurrentValue)
		}
	})

	t.Run("Estimated", func(t *testing.T) {
		snapshots := []*collector.Signals{
			{
				Timestamp: now,
				FD: &collector.FDSnapshot{
					GrowthRate: 10.0,
				},
			},
			{
				Timestamp: now.Add(10 * time.Second),
				FD: &collector.FDSnapshot{
					GrowthRate: 10.0,
					NetDelta:   100, // snapshot level NetDelta
					Entries: []collector.FDEntry{
						{PID: 1234, Comm: "leak-proc", GrowthRate: 10.0, NetDelta: 100, CurrentFDs: 0},
					},
				},
			},
		}

		report := Predict(snapshots)
		var fdPred *Prediction
		for i := range report.Predictions {
			if report.Predictions[i].Signal == "fd" {
				fdPred = &report.Predictions[i]
				break
			}
		}

		if fdPred == nil {
			t.Fatal("expected fd prediction, got none")
		}

		// limit is 65536. NetDelta is 100. remaining is 65436.
		// avgRate is 10.0. etaSecs is 6543.6.
		expectedETA := 6543600 * time.Millisecond // 6543.6s
		if fdPred.TimeToImpact != expectedETA {
			t.Errorf("expected TimeToImpact to be %v, got %v", expectedETA, fdPred.TimeToImpact)
		}

		if fdPred.Limit != "ulimit 65536" {
			t.Errorf("expected Limit to be 'ulimit 65536', got %q", fdPred.Limit)
		}

		if !strings.Contains(fdPred.CurrentValue, "live count unavailable") {
			t.Errorf("expected CurrentValue to contain 'live count unavailable', got %q", fdPred.CurrentValue)
		}
	})
}
