// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
	"github.com/optiqor/kerno/internal/doctor"
)

func TestOOMKillFindingFromCapturedSnapshot(t *testing.T) {
	signals := &collector.Signals{
		Timestamp: time.Now(),
		Duration:  30 * time.Second,
		OOM: &collector.OOMSnapshot{
			Events: []collector.OOMEventEntry{
				{
					PID:        1234,
					Comm:       "oom-victim",
					OOMScore:   900,
					RSSPages:   100000,
					TotalPages: 110000,
				},
			},
			Count: 1,
		},
	}

	findings := doctor.Evaluate(signals, config.Default().Doctor.Thresholds)

	found := false
	for _, finding := range findings {
		if finding.Rule == "oom_kill_occurred" && finding.Severity == doctor.SeverityCritical {
			found = true
			if finding.Process != "oom-victim" {
				t.Fatalf("expected process oom-victim, got %q", finding.Process)
			}
			break
		}
	}

	if !found {
		t.Fatalf("expected oom_kill_occurred finding, got %#v", findings)
	}
}
