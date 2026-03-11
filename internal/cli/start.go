// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func newStartCmd() *cobra.Command {
	var (
		prometheus bool
		dashboard  bool
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start Kerno as a long-running daemon with all collectors",
		Long: `Start Kerno in daemon mode: loads all eBPF programs, starts collectors,
and exposes Prometheus metrics and an optional web dashboard.

This is the command used in the Kubernetes DaemonSet and for
long-running observability on standalone servers.`,
		Example: `  # Start with Prometheus metrics
  sudo kerno start

  # Start with web dashboard
  sudo kerno start --dashboard

  # Start with custom listen addresses
  sudo kerno start --prometheus=:9090 --dashboard=:8080`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStart(cmd.Context(), prometheus, dashboard)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&prometheus, "prometheus", true, "enable Prometheus /metrics endpoint")
	flags.BoolVar(&dashboard, "dashboard", false, "enable the embedded web dashboard")

	return cmd
}

func runStart(ctx context.Context, prometheus bool, dashboard bool) error {
	logger := slog.Default()

	logger.Info("starting kerno daemon",
		"prometheus", prometheus,
		"dashboard", dashboard,
	)

	// Set up OS signal handling for graceful shutdown.
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// TODO(phase-4): Implement daemon startup:
	//   1. Detect environment (K8s, systemd, bare metal)
	//   2. Load eBPF programs
	//   3. Start all enabled collectors
	//   4. Start Prometheus HTTP server (if enabled)
	//   5. Start dashboard HTTP server (if enabled)
	//   6. Block until signal

	fmt.Println("kerno daemon starting...")
	fmt.Printf("  Prometheus:  %v\n", prometheus)
	fmt.Printf("  Dashboard:   %v\n", dashboard)
	fmt.Println()
	fmt.Println("  Waiting for implementation (Phase 4).")
	fmt.Println("  Press Ctrl+C to stop.")

	// Block until shutdown signal.
	<-ctx.Done()

	logger.Info("shutting down kerno daemon")

	// TODO(phase-4): Graceful shutdown:
	//   1. Stop collectors
	//   2. Drain ring buffers
	//   3. Close BPF links
	//   4. Flush metrics
	//   5. Stop HTTP servers

	return nil
}
