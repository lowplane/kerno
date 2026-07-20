// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/adapter"
	"github.com/optiqor/kerno/internal/audit"
	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/config"
	"github.com/optiqor/kerno/internal/metrics"
	"github.com/optiqor/kerno/internal/version"
)

// globalCfg is the live configuration pointer, protected by atomic.Pointer
// so the SIGHUP handler can safely swap it without blocking reads from
// other subsystems. Every read site calls getCfg() and every write calls
// setCfg(); atomic.Pointer provides sequentially-consistent load/store.
var globalCfg atomic.Pointer[config.Config]

// getCfg returns the current live config. Safe to call from any goroutine.
func getCfg() *config.Config {
	return globalCfg.Load()
}

// setCfg atomically replaces the live config pointer.
// Used by the SIGHUP handler after a successful reload.
func setCfg(newCfg *config.Config) {
	globalCfg.Store(newCfg)
}

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
and exposes Prometheus metrics and an optional web dashboard.`,
		Example: `  sudo kerno start
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

// reloadableSubsystems groups every live subsystem that the SIGHUP handler
// may update. loadedCount and totalLoaders are written once at construction
// and never mutated, so no mutex is needed.
//
// httpServer must not be copied after first use; always access via pointer
// to this struct so atomic.Pointer's noCopy invariant is respected.
type reloadableSubsystems struct {
	httpServer   atomic.Pointer[http.Server]
	opts         startOpts
	loadedCount  int
	totalLoaders int
}

func runStart(ctx context.Context, opts startOpts) error {
	if err := requireRoot(); err != nil {
		return err
	}

	logger := slog.Default()

	// Phase 0: Audit logger
	auditLog, err := audit.New(audit.Config{
		FilePath:   cfg.Audit.FilePath,
		MaxSizeMB:  cfg.Audit.MaxSizeMB,
		MaxBackups: cfg.Audit.MaxBackups,
		Stderr:     cfg.Audit.Stderr,
	})
	if err != nil {
		logger.Error("failed to initialise audit logger; audit events will be lost", "error", err)
		auditLog = audit.Noop()
	}

	// daemon.panic recovery — stack digest audit log mein, full trace stderr mein.
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			logger.Error("daemon panic recovered", "panic", r, "stack", string(stack))
			auditLog.RecordPanic(version.Version, stack)
			panic(r) // re-panic — process must exit non-zero
		}
	}()

	// daemon.start — pehli auditable event.
	auditLog.Record("kerno/start", audit.EventDaemonStart, audit.DaemonDetails{
		Version: version.Version,
	})

	// daemon.stop — hamesha last auditable event hogi.
	defer auditLog.Record("kerno/start", audit.EventDaemonStop, audit.DaemonDetails{
		Version: version.Version,
	})

	logger.Info("starting kerno daemon",
		"prometheus", opts.prometheus,
		"dashboard", opts.dashboard,
		"version", version.Version,
	)

	// SIGINT/SIGTERM trigger graceful shutdown via context cancellation.
	// SIGHUP triggers config hot-reload in a dedicated goroutine.
	shutdownCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	// Initialise the atomic config pointer with the startup config.
	// cfg is the package-level *config.Config set by root.go's initConfig.
	startupCfg := cfg
	setCfg(startupCfg)

	// Resolve Prometheus listen address; CLI flag overrides config file.
	promAddr := startupCfg.Prometheus.Addr
	if opts.prometheusAddr != "" {
		promAddr = opts.prometheusAddr
	}

	// Phase 1: load eBPF programs with graceful degradation.
	// FIX: buildLoaders now returns a single []bpf.Loader (not two slices).
	loaders := buildLoaders(logger)
	loadedCount := 0
	closers := make([]func(), 0, len(loaders))

	for _, l := range loaders {
		closer, err := l.Load()
		if err != nil {
			auditLog.RecordBPFLoad(l.Name(), false, err)
			logger.Warn("failed to load eBPF program, skipping", "program", l.Name(), "error", err)
			continue
		}
		auditLog.RecordBPFLoad(l.Name(), true, nil)
		closers = append(closers, func() { _ = closer.Close() })
		loadedCount++
		logger.Info("loaded eBPF program", "program", l.Name())
	}

	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	totalLoaders := len(loaders)
	logger.Info("eBPF programs loaded", "loaded", loadedCount, "total", totalLoaders)

	metrics.BPFProgramsLoaded.Set(float64(loadedCount))
	metrics.InfoMetric.WithLabelValues(version.Version).Set(1)

	// Pre-initialise CounterVec instances so /metrics emits HELP/TYPE
	// lines immediately, before any event flows through.
	for _, l := range loaders {
		metrics.CollectorEventsTotal.WithLabelValues(l.Name()).Add(0)
		metrics.CollectorErrorsTotal.WithLabelValues(l.Name()).Add(0)
	}

	// Phase 2: metrics bridge.
	// FIX: pass loaders directly instead of loaderSet.Loaders().
	bridge := metrics.NewBridge(logger)
	bridge.Start(shutdownCtx, loaders)
	defer bridge.Stop()

	// Phase 2b: environment adapter.
	env := adapter.DetectEnvironment()
	adpt := adapter.NewAdapter(logger, env)
	if err := adpt.Start(shutdownCtx); err != nil {
		logger.Warn("failed to start environment adapter", "error", err)
	}
	defer adpt.Stop()
	logger.Info("environment adapter started", "adapter", adpt.Name(), "env", env)

	// Phase 3: HTTP server (health + metrics).
	// reloadableSubs is heap-allocated via & so atomic.Pointer fields are
	// never copied; all access goes through the pointer.
	reloadableSubs := &reloadableSubsystems{
		opts:         opts,
		loadedCount:  loadedCount,
		totalLoaders: totalLoaders,
	}
	if srv := startHTTPServer(logger, opts, promAddr, loadedCount, totalLoaders); srv != nil {
		reloadableSubs.httpServer.Store(srv)
	}

	// SIGHUP goroutine: runs for the lifetime of the daemon.
	// On every SIGHUP it re-reads the config file, diffs old vs new,
	// applies safe changes in-place, and warns about restart-required changes.
	go func() {
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-sighupCh:
				handleSIGHUP(reloadableSubs)
			}
		}
	}()

	fmt.Println("kerno daemon running")
	fmt.Printf("  eBPF programs: %d/%d loaded\n", loadedCount, totalLoaders)
	if opts.prometheus {
		fmt.Printf("  Prometheus:    http://%s/metrics\n", promAddr)
		fmt.Printf("  Health:        http://%s/healthz\n", promAddr)
		fmt.Printf("  Readiness:     http://%s/readyz\n", promAddr)
	}
	if opts.dashboard {
		fmt.Printf("  Dashboard:     http://%s (not yet implemented)\n", getCfg().Dashboard.Addr)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	<-shutdownCtx.Done()

	logger.Info("shutting down kerno daemon")

	// Phase 4: graceful HTTP shutdown.
	if srv := reloadableSubs.httpServer.Load(); srv != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := srv.Shutdown(stopCtx); err != nil {
			logger.Warn("HTTP server shutdown error", "error", err)
		}
	}

	logger.Info("kerno daemon stopped")
	return nil
}

// handleSIGHUP performs config hot-reload. Called from the SIGHUP goroutine
// in runStart; must not block for long.
func handleSIGHUP(subs *reloadableSubsystems) {
	// Always read the logger via slog.Default() so we pick up any level
	// changes applied by a previous reload without holding a stale pointer.
	logger := slog.Default()

	oldCfg := getCfg()
	logger.Info("SIGHUP received, reloading config", "path", cfgFile)

	// FIX: ReloadFrom is now defined on *config.Config in config.go.
	newCfg, result, err := oldCfg.ReloadFrom(cfgFile)
	if err != nil {
		logger.Error("config reload failed, keeping current config", "error", err)
		return
	}

	for _, change := range result.Applied {
		logger.Info("applying hot-reload change", "change", change)
	}

	// 1. Log level/format: rebuild the slog handler via root.go's initLogger,
	//    which calls slog.SetDefault so every subsequent slog.Default() call
	//    (including the next SIGHUP) picks up the new handler automatically.
	if oldCfg.LogLevel != newCfg.LogLevel || oldCfg.LogFormat != newCfg.LogFormat {
		initLogger(newCfg.LogLevel, newCfg.LogFormat)
		slog.Default().Info("log level changed",
			"level", newCfg.LogLevel, "format", newCfg.LogFormat)
	}

	// 2. Prometheus address/enabled: rebind the HTTP server if either changed.
	// loadedCount and totalLoaders are written once at construction; read directly.
	oldAddr := oldCfg.Prometheus.Addr
	newAddr := newCfg.Prometheus.Addr
	if subs.opts.prometheusAddr != "" {
		// CLI flag always wins; honour it on reload too.
		newAddr = subs.opts.prometheusAddr
	}
	if oldAddr != newAddr || oldCfg.Prometheus.Enabled != newCfg.Prometheus.Enabled {
		logger.Info("prometheus config changed, rebinding",
			"old", oldAddr, "new", newAddr)
		rebindPrometheus(logger, &subs.httpServer, newAddr,
			subs.loadedCount, subs.totalLoaders,
			newCfg.Prometheus.Enabled,
		)
	}

	// 3. Warn about changes that need a full daemon restart.
	for _, w := range result.RestartRequired {
		logger.Warn("config change requires restart to take effect", "change", w)
	}

	// Atomically swap the global config pointer so the next reload diffs
	// against the freshly-applied config, not the stale startup config.
	setCfg(newCfg)

	logger.Info(result.String(),
		"applied", len(result.Applied),
		"restart_required", len(result.RestartRequired),
	)
}

// startHTTPServer launches the Prometheus/health HTTP server and returns
// the *http.Server so the caller can shut it down on exit.
func startHTTPServer(
	logger *slog.Logger,
	opts startOpts,
	addr string,
	loadedCount, total int,
) *http.Server {
	if !opts.prometheus {
		return nil
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		logger.Error("failed to start HTTP server", "addr", addr, "error", err)
		return nil
	}

	srv := buildHTTPServer(addr, loadedCount, total)
	go func() {
		logger.Info("starting HTTP server", "addr", addr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	return srv
}

// rebindPrometheus gracefully shuts down the current HTTP server and starts
// a new one on newAddr. Called when prometheus.addr or prometheus.enabled
// changes on SIGHUP.
func rebindPrometheus(
	logger *slog.Logger,
	srvPtr *atomic.Pointer[http.Server],
	newAddr string,
	loadedCount, total int,
	enabled bool,
) {
	old := srvPtr.Load()

	if old != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := old.Shutdown(ctx); err != nil {
			logger.Warn("old HTTP server shutdown during rebind", "error", err)
		}
	}

	if !enabled {
		srvPtr.Store(nil)
		logger.Info("prometheus disabled, HTTP server stopped")
		return
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", newAddr)
	if err != nil {
		logger.Error("prometheus rebind failed, no metrics server running",
			"addr", newAddr, "error", err)
		srvPtr.Store(nil)
		return
	}

	srv := buildHTTPServer(newAddr, loadedCount, total)
	srvPtr.Store(srv)
	go func() {
		logger.Info("HTTP server restarted", "addr", newAddr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error after rebind", "error", err)
		}
	}()
}

// buildHTTPServer assembles the mux and http.Server without starting it.
func buildHTTPServer(addr string, loadedCount, total int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler(loadedCount, total))
	mux.HandleFunc("/readyz", healthzHandler(loadedCount, total))
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// buildLoaders creates the set of BPF loaders based on the current live config.
// FIX: returns a single []bpf.Loader instead of two identical slices.
// The second return value (loaderSet) was unused and caused the
// loaderSet.Loaders() compile error — it's been removed entirely.
func buildLoaders(logger *slog.Logger) []bpf.Loader {
	currentCfg := getCfg()
	if currentCfg == nil {
		currentCfg = cfg
	}

	var loaders []bpf.Loader

	if currentCfg.Collectors.SyscallLatency {
		loaders = append(loaders, bpf.NewSyscallLatencyLoader(logger))
	}
	if currentCfg.Collectors.TCPMonitor {
		loaders = append(loaders, bpf.NewTCPMonitorLoader(logger))
	}
	if currentCfg.Collectors.OOMTrack {
		loaders = append(loaders, bpf.NewOOMTrackLoader(logger))
	}
	if currentCfg.Collectors.DiskIO {
		loaders = append(loaders, bpf.NewDiskIOLoader(logger))
	}
	if currentCfg.Collectors.SchedDelay {
		loaders = append(loaders, bpf.NewSchedDelayLoader(logger))
	}
	if currentCfg.Collectors.FDTrack {
		loaders = append(loaders, bpf.NewFDTrackLoader(logger))
	}

	return loaders
}

// healthzHandler returns an HTTP handler that reports BPF program load status.
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
