// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// requireRoot checks that the process is running as root.
// eBPF programs require CAP_BPF + CAP_PERFMON at minimum, which
// typically means running as root.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (eBPF); re-run with sudo")
	}
	return nil
}

// resolveOutput returns the output format from the command's local --output
// flag, falling back to the root persistent --output flag.
func resolveOutput(cmd *cobra.Command) string {
	if cmd.Flags().Changed("output") {
		o, _ := cmd.Flags().GetString("output")
		return o
	}
	o, _ := cmd.Root().PersistentFlags().GetString("output")
	if o == "" {
		return "pretty"
	}
	return o
}

// formatLatency renders a time.Duration as a human-friendly latency string.
func formatLatency(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fus", float64(d.Nanoseconds())/1e3)
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

// formatBytes renders a byte count as a human-friendly string.
func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// isTerminal returns true if stdout is connected to a terminal.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// formatDev renders a device number as major:minor.
func formatDev(dev uint32) string {
	major := (dev >> 20) & 0xFFF
	minor := dev & 0xFFFFF
	return fmt.Sprintf("%d:%d", major, minor)
}
