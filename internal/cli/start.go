// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/tls"
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
	"github.com/optiqor/kerno/internal/auth"
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
	loaders := buildLoaders(logger)
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
	bridge.Start(ctx, loaders)
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
	var healthServer *http.Server

	if opts.prometheus {

		metricsMux := http.NewServeMux()
		metricsHandler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})

		if cfg.Prometheus.Auth.Mode == "bearer" {
			guard, err := auth.NewBearerGuard(cfg.Prometheus.Auth.TokenFile, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize bearer auth: %w", err)
			}
			metricsHandler = guard.Wrap(metricsHandler)

			// Setup SIGHUP listener for hot-reloading the token without restart.
			sighupCh := make(chan os.Signal, 1)
			signal.Notify(sighupCh, syscall.SIGHUP)
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-sighupCh:
						if err := guard.Reload(cfg.Prometheus.Auth.TokenFile); err != nil {
							logger.Error("failed to reload bearer token", "error", err)
						}
					}
				}
			}()
		}

		metricsMux.Handle("/metrics", metricsHandler)

		// Build TLS config when cert material is present.
		// - mtls: mandatory (cert + key + ca).
		// - bearer: optional (cert + key only → one-way TLS so the token
		//   is not sent in cleartext on the node wire).
		// - none: no TLS.
		var tlsCfg *tls.Config
		if cfg.Prometheus.Auth.CertFile != "" {
			caFile := cfg.Prometheus.Auth.CACertFile
			var err error
			tlsCfg, err = auth.TLSConfig(cfg.Prometheus.Auth.CertFile, cfg.Prometheus.Auth.KeyFile, caFile)
			if err != nil {
				return fmt.Errorf("failed to initialize TLS: %w", err)
			}
		}

		// For none and bearer the health probes stay on the metrics mux so
		// existing systemd units, LB checks, and the chart's httpGet probes
		// that hit :9090/healthz keep working after upgrade.
		//
		// For mtls the listener runs ListenAndServeTLS which forces every
		// client to present a cert — kubelet probes can't do that, so we
		// split health onto a dedicated plain-HTTP listener.
		if cfg.Prometheus.Auth.Mode == "mtls" {
			healthMux := http.NewServeMux()
			healthMux.HandleFunc("/healthz", healthzHandler(loadedCount, len(loaders)))
			healthMux.HandleFunc("/readyz", healthzHandler(loadedCount, len(loaders)))

			healthAddr := cfg.Prometheus.HealthAddr
			if healthAddr == "" {
				healthAddr = ":9092"
			}

			healthServer = &http.Server{
				Addr:              healthAddr,
				Handler:           healthMux,
				ReadHeaderTimeout: 10 * time.Second,
			}

			go func() {
				logger.Info("starting health HTTP server", "addr", healthAddr)
				if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logger.Error("health HTTP server error", "error", err)
				}
			}()
		} else {
			// none / bearer: health endpoints live on the metrics mux.
			metricsMux.HandleFunc("/healthz", healthzHandler(loadedCount, len(loaders)))
			metricsMux.HandleFunc("/readyz", healthzHandler(loadedCount, len(loaders)))
		}

		httpServer = &http.Server{
			Addr:              promAddr,
			Handler:           metricsMux,
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         tlsCfg,
		}

		go func() {
			logger.Info("starting metrics HTTP server", "addr", promAddr, "auth_mode", cfg.Prometheus.Auth.Mode)
			var err error
			if tlsCfg != nil {
				// Certs are already loaded into TLSConfig
				err = httpServer.ListenAndServeTLS("", "")
			} else {
				err = httpServer.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics HTTP server error", "error", err)
			}
		}()
	}

	// Log daemon status.
	fmt.Println("kerno daemon running")
	fmt.Printf("  eBPF programs: %d/%d loaded\n", loadedCount, len(loaders))
	if opts.prometheus {
		schema := "http"
		if cfg.Prometheus.Auth.CertFile != "" {
			schema = "https"
		}
		fmt.Printf("  Prometheus:    %s://%s/metrics\n", schema, promAddr)
		if cfg.Prometheus.Auth.Mode == "mtls" {
			healthAddr := cfg.Prometheus.HealthAddr
			if healthAddr == "" {
				healthAddr = ":9092"
			}
			fmt.Printf("  Health:        http://%s/healthz\n", healthAddr)
			fmt.Printf("  Readiness:     http://%s/readyz\n", healthAddr)
		} else {
			fmt.Printf("  Health:        %s://%s/healthz\n", schema, promAddr)
			fmt.Printf("  Readiness:     %s://%s/readyz\n", schema, promAddr)
		}
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
			logger.Warn("metrics HTTP server shutdown error", "error", err)
		}
	}
	if healthServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := healthServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("health HTTP server shutdown error", "error", err)
		}
	}

	logger.Info("kerno daemon stopped")
	return nil
}

// buildLoaders creates the set of BPF loaders based on config.
func buildLoaders(logger *slog.Logger) []bpf.Loader {
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

	return loaders
}

// healthzHandler returns the liveness probe handler.
func healthzHandler(loaded, total int) http.HandlerFunc {
	startTime := time.Now()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "ok",
			"version":         version.Version,
			"uptime":          time.Since(startTime).Seconds(),
			"programs_loaded": loaded,
			"programs_total":  total,
		})
	}
}

// readyzHandler returns the readiness probe handler.
func readyzHandler(loaded, total int) http.HandlerFunc {
	startTime := time.Now()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Ready with atleast one BPF program is loaded
		// Partial loads are acceptable due to graceful degradation
		if loaded == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"status":          "not_ready",
				"programs_loaded": loaded,
				"programs_total":  total,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "ready",
			"programs_loaded": loaded,
			"programs_total":  total,
			"uptime":          time.Since(startTime).Seconds(),
		})
	}
}
