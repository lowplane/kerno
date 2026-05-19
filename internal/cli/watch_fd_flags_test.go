// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

// TestNewWatchFDCmd_Flags verifies the watch fd command
// exposes all documented flags.
func TestNewWatchFDCmd_Flags(t *testing.T) {
	cmd := newWatchFDCmd()

	wantFlags := []string{
		"threshold",
		"interval",
		"duration",
		"output",
	}

	for _, name := range wantFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("watch fd cmd missing --%s flag", name)
		}
	}

	// -o shorthand for --output.
	if cmd.Flags().ShorthandLookup("o") == nil {
		t.Error("watch fd cmd missing -o shorthand for --output")
	}
}

func TestNewWatchFDCmd_Defaults(t *testing.T) {
	cmd := newWatchFDCmd()

	cases := []struct {
		flag string
		want string
	}{
		{"threshold", "10"},
		{"interval", "5s"},
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
