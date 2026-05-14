// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"
)

func newTraceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace kernel events in real-time",
		Long: `Trace streams raw eBPF events to stdout with optional filtering.
Each subcommand traces a specific signal dimension.

Requires root privileges for eBPF program loading.`,
		Example: `  # Stream syscall events for PID 1234
  sudo kerno trace syscall --pid 1234

  # Show only slow disk writes
  sudo kerno trace disk --op write --threshold 10ms

  # Watch scheduler delays above 5ms
  sudo kerno trace sched --threshold 5ms`,
	}

	cmd.AddCommand(
		newTraceSyscallCmd(),
		newTraceDiskCmd(),
		newTraceSchedCmd(),
	)

	return cmd
}
