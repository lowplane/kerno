// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestVerboseFlagRegistered verifies that the --verbose / -v flag is present
// on the root command with the expected metadata.
func TestVerboseFlagRegistered(t *testing.T) {
	root := New()

	f := root.PersistentFlags().Lookup("verbose")
	if f == nil {
		t.Fatal("--verbose flag not registered on root command")
	}
	if f.Shorthand != "v" {
		t.Errorf("expected shorthand -v, got %q", f.Shorthand)
	}
	if f.DefValue != "false" {
		t.Errorf("expected default false, got %q", f.DefValue)
	}
	if f.Value.String() != "false" {
		t.Errorf("verbose should be false before any flag is set, got %q", f.Value.String())
	}
}

// TestVerboseFlagInheritedBySubcommands ensures every subcommand inherits
// --verbose as a persistent flag from the root, so `kerno doctor -v` works.
func TestVerboseFlagInheritedBySubcommands(t *testing.T) {
	root := New()

	subcommands := []string{"doctor", "start", "trace", "watch", "audit", "chaos", "version", "explain"}
	for _, name := range subcommands {
		sub := findCmd(root, name)
		if sub == nil {
			// Not every build includes every command; skip gracefully.
			t.Logf("subcommand %q not found, skipping inheritance check", name)
			continue
		}
		if sub.InheritedFlags().Lookup("verbose") == nil {
			t.Errorf("subcommand %q does not inherit --verbose from root", name)
		}
	}
}

// TestVerboseAndLogLevelAreDistinctFlags ensures --verbose and --log-level
// remain separate flags and do not shadow each other.
func TestVerboseAndLogLevelAreDistinctFlags(t *testing.T) {
	root := New()
	pf := root.PersistentFlags()

	logLevel := pf.Lookup("log-level")
	verbose := pf.Lookup("verbose")

	if logLevel == nil {
		t.Fatal("--log-level flag missing from root")
	}
	if verbose == nil {
		t.Fatal("--verbose flag missing from root")
	}
	if logLevel.Name == verbose.Name {
		t.Error("--log-level and --verbose must be distinct flags")
	}
}

// findCmd returns the named direct subcommand of root, or nil if absent.
func findCmd(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
