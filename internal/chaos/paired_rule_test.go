// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import "testing"

// validDoctorRules is a hand-maintained list mirroring the rule names
// in internal/doctor/rules.go. We avoid importing the doctor package
// here to keep chaos a leaf — so this list must stay in sync with
// rules.go. The test below enforces the invariant.
var validDoctorRules = map[string]bool{
	"disk_io_bottleneck":     true,
	"disk_io_write_high":     true,
	"oom_kill_occurred":      true,
	"oom_imminent":           true,
	"tcp_retransmit_storm":   true,
	"tcp_rtt_degradation":    true,
	"scheduler_contention":   true,
	"fd_leak":                true,
	"syscall_latency_high":   true,
	"syscall_error_rate":     true,
	"memory_limit_pressure":  true,
	"memory_high_throttling": true,
	"healthy_system":         true,
	// "multiple" is a sentinel used by cascade — not a real rule but a
	// recognized placeholder.
	"multiple": true,
}

// TestPairedRulesExistInDoctor enforces that every chaos scenario's
// PairedRule() corresponds to an actual doctor rule. Catches typos
// that would silently mislead users about which rule should fire.
func TestPairedRulesExistInDoctor(t *testing.T) {
	for _, s := range List() {
		rule := s.PairedRule()
		if !validDoctorRules[rule] {
			t.Errorf("scenario %q paired with unknown rule %q",
				s.Name(), rule)
		}
	}
}
