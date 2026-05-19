package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionShortFlag(t *testing.T) {
	cmd := newVersionCmd()

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--short"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := strings.TrimSpace(buf.String())

	if output == "" {
		t.Fatal("expected non-empty output")
	}
}

func TestVersionJSONOutput(t *testing.T) {
	cmd := newVersionCmd()

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--output", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := buf.String()

	for _, want := range []string{
		"version",
		"commit",
		"built",
		"go",
		"platform",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}
