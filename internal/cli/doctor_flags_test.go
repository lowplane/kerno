// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"
)

// TestNewDoctorCmd_Flags verifies the doctor command exposes every
// flag the docs and examples reference.
func TestNewDoctorCmd_Flags(t *testing.T) {
	cmd := newDoctorCmd()

	wantFlags := []string{"duration", "exit-code", "continuous", "interval", "output", "ai", "no-ai", "no-banner"}
	for _, name := range wantFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("doctor cmd missing --%s flag", name)
		}
	}

	// -d shorthand for --duration.
	if cmd.Flags().ShorthandLookup("d") == nil {
		t.Error("doctor cmd missing -d shorthand for --duration")
	}
	// -o shorthand for --output.
	if cmd.Flags().ShorthandLookup("o") == nil {
		t.Error("doctor cmd missing -o shorthand for --output")
	}
}

func TestNewDoctorCmd_Defaults(t *testing.T) {
	cmd := newDoctorCmd()

	cases := []struct {
		flag string
		want string
	}{
		{"duration", "0s"},   // 0 means "use config"
		{"interval", "1m0s"}, // 60s default
		{"exit-code", "false"},
		{"continuous", "false"},
		{"ai", "false"},
		{"no-ai", "false"},
		{"no-banner", "false"},
	}
	for _, c := range cases {
		f := cmd.Flags().Lookup(c.flag)
		if f == nil {
			t.Errorf("flag %q not found", c.flag)
			continue
		}
		if f.DefValue != c.want {
			t.Errorf("--%s default = %q, want %q", c.flag, f.DefValue, c.want)
		}
	}
}

func TestNewDoctorCmd_IntervalParseable(t *testing.T) {
	cmd := newDoctorCmd()
	if err := cmd.Flags().Set("interval", "5s"); err != nil {
		t.Fatalf("Set --interval = 5s: %v", err)
	}
	val, err := cmd.Flags().GetDuration("interval")
	if err != nil {
		t.Fatal(err)
	}
	if val != 5*time.Second {
		t.Errorf("interval = %v, want 5s", val)
	}
}
