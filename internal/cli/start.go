// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/adapter"
	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/metrics"
	"github.com/optiqor/kerno/internal/version"
)

func newStartCmd() *cobra.Command {
	var (
		prometheus     bool
		prometheusAddr string
		dashboard      bool
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

  # Start with custom Prometheus address
  sudo kerno start --prometheus-addr :9091

  # Start with web dashboard
  sudo kerno start --dashboard`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStart(cmd.Context(), startOpts{
				prometheus:     prometheus,
				prometheusAddr: prometheusAddr,
				dashboard:      dashboard,
			})
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&prometheus, "prometheus", true, "enable Prometheus /metrics endpoint")
	flags.StringVar(&prometheusAddr, "prometheus-addr", "", "Prometheus listen address (default from config)")
	flags.BoolVar(&dashboard, "dashboard", false, "enable the embedded web dashboard")

	return cmd
}

type startOpts struct {
	prometheus     bool
	prometheusAddr string
	dashboard      bool
}

func runStart(ctx context.Context, opts startOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()

	logger.Info("starting kerno daemon",
		"prometheus", opts.prometheus,
		"dashboard", opts.dashboard,
	)

	// Set up OS signal handling for graceful shutdown.
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Resolve Prometheus address.
	promAddr := cfg.Prometheus.Addr
	if opts.prometheusAddr != "" {
		promAddr = opts.prometheusAddr
	}

	// Phase 1: Load eBPF programs with graceful degradation.
	loaders, loaderSet := buildLoaders(logger)
	loadedCount := 0
	closers := make([]func(), 0, len(loaders))

	for _, l := range loaders {
		closer, err := l.Load()
		if err != nil {
			logger.Warn("failed to load eBPF program, skipping",
				"program", l.Name(),
				"error", err,
			)
			continue
		}
		closers = append(closers, func() { _ = closer.Close() })
		loadedCount++
		logger.Info("loaded eBPF program", "program", l.Name())
	}

	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	logger.Info("eBPF programs loaded", "loaded", loadedCount, "total", len(loaders))

	// Set Prometheus gauges for self-monitoring.
	metrics.BPFProgramsLoaded.Set(float64(loadedCount))
	metrics.InfoMetric.WithLabelValues(version.Version).Set(1)

	// Pre-initialize CounterVec instances so /metrics emits HELP/TYPE
	// lines immediately, before any event flows. Without this,
	// CounterVec metrics with no observations don't show up — making
	// /metrics look empty for the first few seconds and breaking
	// scrapers that auto-discover metric names from a single fetch.
	for _, l := range loaders {
		metrics.CollectorEventsTotal.WithLabelValues(l.Name()).Add(0)
		metrics.CollectorErrorsTotal.WithLabelValues(l.Name()).Add(0)
	}

	// Phase 2: Start the metrics bridge — reads BPF events and feeds Prometheus.
	bridge := metrics.NewBridge(logger)
	bridge.Start(ctx, loaderSet.Loaders())
	defer bridge.Stop()

	// Phase 2b: Start environment adapter for event enrichment.
	env := adapter.DetectEnvironment()
	adpt := adapter.NewAdapter(logger, env)
	if err := adpt.Start(ctx); err != nil {
		logger.Warn("failed to start environment adapter", "error", err)
	}
	defer adpt.Stop()
	logger.Info("environment adapter started", "adapter", adpt.Name(), "env", env)

	// Phase 3: Start HTTP server for health and metrics.
	var httpServer *http.Server
	if opts.prometheus {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", healthzHandler(loadedCount, len(loaders)))
		mux.HandleFunc("/readyz", healthzHandler(loadedCount, len(loaders)))
		mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))

		httpServer = &http.Server{
			Addr:              promAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			logger.Info("starting HTTP server", "addr", promAddr)
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("HTTP server error", "error", err)
			}
		}()
	}

	// Log daemon status.
	fmt.Println("kerno daemon running")
	fmt.Printf("  eBPF programs: %d/%d loaded\n", loadedCount, len(loaders))
	if opts.prometheus {
		fmt.Printf("  Prometheus:    http://%s/metrics\n", promAddr)
		fmt.Printf("  Health:        http://%s/healthz\n", promAddr)
		fmt.Printf("  Readiness:     http://%s/readyz\n", promAddr)
	}
	if opts.dashboard {
		fmt.Printf("  Dashboard:     http://%s (not yet implemented)\n", cfg.Dashboard.Addr)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	// Block until shutdown signal.
	<-ctx.Done()

	logger.Info("shutting down kerno daemon")

	// Phase 4: Graceful shutdown.
	if httpServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("HTTP server shutdown error", "error", err)
		}
	}

	logger.Info("kerno daemon stopped")
	return nil
}

// buildLoaders creates the set of BPF loaders based on config.
func buildLoaders(logger *slog.Logger) ([]bpf.Loader, *bpf.LoaderSet) {
	var loaders []bpf.Loader

	if cfg.Collectors.SyscallLatency {
		loaders = append(loaders, bpf.NewSyscallLatencyLoader(logger))
	}
	if cfg.Collectors.TCPMonitor {
		loaders = append(loaders, bpf.NewTCPMonitorLoader(logger))
	}
	if cfg.Collectors.OOMTrack {
		loaders = append(loaders, bpf.NewOOMTrackLoader(logger))
	}
	if cfg.Collectors.DiskIO {
		loaders = append(loaders, bpf.NewDiskIOLoader(logger))
	}
	if cfg.Collectors.SchedDelay {
		loaders = append(loaders, bpf.NewSchedDelayLoader(logger))
	}
	if cfg.Collectors.FDTrack {
		loaders = append(loaders, bpf.NewFDTrackLoader(logger))
	}

	set := bpf.NewLoaderSet(logger, loaders...)
	return loaders, set
}

// healthzHandler returns the health check handler.
func healthzHandler(loaded, total int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "ok",
			"programsLoaded": loaded,
			"programsTotal":  total,
		})
	}
}
