// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunChaosListShowsAllScenarios(t *testing.T) {
	var buf bytes.Buffer
	if err := runChaosList(&buf); err != nil {
		t.Fatalf("runChaosList: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"SCENARIO", "PAIRED RULE", "DESCRIPTION",
		"cpu", "fd-leak", "memory", "disk-sat", "tcp-churn", "cascade",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestNewChaosCmd_FlagsRegistered(t *testing.T) {
	cmd := newChaosCmd()

	for _, name := range []string{"induce", "list", "duration", "intensity", "yes"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("chaos cmd missing --%s flag", name)
		}
	}
	if cmd.Flags().ShorthandLookup("y") == nil {
		t.Error("chaos cmd missing -y shorthand")
	}
}
