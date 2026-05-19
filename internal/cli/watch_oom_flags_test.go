// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

// TestNewWatchOOMCmd_Flags verifies the watch oom command
// exposes all documented flags.
func TestNewWatchOOMCmd_Flags(t *testing.T) {
	cmd := newWatchOOMCmd()

	wantFlags := []string{
		"threshold",
		"alert",
		"duration",
		"output",
	}

	for _, name := range wantFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("watch oom cmd missing --%s flag", name)
		}
	}

	// -o shorthand for --output.
	if cmd.Flags().ShorthandLookup("o") == nil {
		t.Error("watch oom cmd missing -o shorthand for --output")
	}
}

func TestNewWatchOOMCmd_Defaults(t *testing.T) {
	cmd := newWatchOOMCmd()

	cases := []struct {
		flag string
		want string
	}{
		{"threshold", "0"},
		{"alert", "false"},
		{"duration", "0s"},
		{"output", ""},
	}

	for _, c := range cases {
		f := cmd.Flags().Lookup(c.flag)
		if f == nil {
			t.Errorf("flag %q not found", c.flag)
			continue
		}

		if f.DefValue != c.want {
			t.Errorf("--%s default = %q, want %q",
				c.flag, f.DefValue, c.want)
		}
	}
}
