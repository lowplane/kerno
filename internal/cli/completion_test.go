// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"testing"
)

func TestCompletionCmd(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			cmd := New()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs([]string{"completion", shell})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("%s: %v", shell, err)
			}
			if buf.Len() == 0 {
				t.Errorf("%s: empty completion output", shell)
			}
		})
	}
}
