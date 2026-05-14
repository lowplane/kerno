// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"
)

func newWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Monitor aggregated kernel metrics",
		Long: `Watch aggregates eBPF events over time windows and displays periodic summaries.
Each subcommand monitors a specific signal dimension with threshold-based alerting.

Requires root privileges for eBPF program loading.`,
		Example: `  # Monitor TCP connections with retransmits
  sudo kerno watch tcp --retransmits

  # Watch for OOM kills with alert banners
  sudo kerno watch oom --alert

  # Monitor file descriptor leaks
  sudo kerno watch fd --threshold 5`,
	}

	cmd.AddCommand(
		newWatchTCPCmd(),
		newWatchOOMCmd(),
		newWatchFDCmd(),
	)

	return cmd
}
