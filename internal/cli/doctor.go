// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/optiqor/kerno/internal/adapter"
	"github.com/optiqor/kerno/internal/ai"
	"github.com/optiqor/kerno/internal/bpf"
	"github.com/optiqor/kerno/internal/collector"
	"github.com/optiqor/kerno/internal/config"
	"github.com/optiqor/kerno/internal/doctor"
)

func newDoctorCmd() *cobra.Command {
	var (
		duration     time.Duration
		exitCode     bool
		continuous   bool
		interval     time.Duration
		output       string
		useAI        bool
		noAI         bool
		quiet        bool
		noBanner     bool
		onlyCritical bool
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run a 30-second automated kernel diagnostic",
		Long: `Kerno Doctor collects kernel signals via eBPF for 30 seconds (configurable),
analyzes them against diagnostic rules, and prints a ranked report of findings.

This is the primary entry point for kernel troubleshooting. No configuration needed.
Add --ai to enrich findings with AI-powered analysis (requires API key).`,
		Example: `  # Run a standard 30-second diagnostic
  sudo kerno doctor

  # Quick 10-second check
  sudo kerno doctor --duration 10s

  # Machine-readable output for CI/CD
  sudo kerno doctor --output json --exit-code

  # Continuous monitoring
  sudo kerno doctor --continuous --interval 60s

  # Enable AI analysis
  sudo kerno doctor --ai`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Inherit --output from root if not set via doctor flag.
			if output == "" {
				output, _ = cmd.Root().PersistentFlags().GetString("output")
			}

			// Resolve AI enable/disable: --ai flag overrides config, --no-ai forces off.
			aiEnabled := cfg.AI.Enabled
			if useAI {
				aiEnabled = true
			}
			if noAI {
				aiEnabled = false
			}

			return runDoctor(cmd.Context(), doctorOpts{
				duration:     duration,
				exitCode:     exitCode,
				continuous:   continuous,
				interval:     interval,
				output:       output,
				aiEnabled:    aiEnabled,
				quiet:        quiet,
				noBanner:     noBanner,
				onlyCritical: onlyCritical,
			})
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", 0, "analysis duration (default: from config, typically 30s)")
	flags.BoolVar(&exitCode, "exit-code", false, "exit 1 if critical findings exist (for CI/CD)")
	flags.BoolVar(&continuous, "continuous", false, "re-run analysis at regular intervals")
	flags.DurationVar(&interval, "interval", 60*time.Second, "interval between runs in continuous mode")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json (overrides global --output)")
	flags.BoolVar(&useAI, "ai", false, "enable AI-powered analysis (requires API key)")
	flags.BoolVar(&noAI, "no-ai", false, "disable AI analysis even if enabled in config")
	flags.BoolVarP(&quiet, "quiet", "q", false, "only emit critical/warning findings (CI-friendly)")
	flags.BoolVar(&noBanner, "no-banner", false, "suppress the ASCII banner block")
	flags.BoolVar(&onlyCritical, "only-critical", false, "show only critical severity items")
	//nolint:errcheck // RegisterFlagCompletionFunc only returns error on invalid flag name, which is static.
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

type doctorOpts struct {
	duration     time.Duration
	exitCode     bool
	continuous   bool
	interval     time.Duration
	output       string
	aiEnabled    bool
	quiet        bool
	noBanner     bool
	onlyCritical bool
}

func runDoctor(ctx context.Context, opts doctorOpts) error {
	// Use config default if no flag override.
	if opts.duration == 0 {
		if cfg != nil {
			opts.duration = cfg.Doctor.Duration
		} else {
			opts.duration = 30 * time.Second
		}
	}
	if opts.output == "" {
		opts.output = "pretty"
	}

	logger := slog.Default()

	// Resolve thresholds from config.
	thresholds := cfg.Doctor.Thresholds

	// Build optional AI analyzer.
	var analyzer doctor.Analyzer
	if opts.aiEnabled {
		var err error
		analyzer, err = buildAnalyzer(cfg, logger)
		if err != nil {
			// AI setup failure is non-fatal — warn and continue without AI.
			logger.Warn("AI analysis unavailable, continuing with rule-based diagnostics", "error", err)
		}
	}

	// Create the diagnostic engine.
	engine := doctor.NewEngine(thresholds, analyzer, logger)

	// Select renderer.
	var renderer doctor.Renderer
	switch opts.output {
	case "json":
		renderer = &doctor.JSONRenderer{Pretty: true}
	default:
		renderer = &doctor.PrettyRenderer{
			NoColor:  viper.GetBool("no_color") || os.Getenv("NO_COLOR") != "" || !isTerminal(),
			NoBanner: opts.noBanner,
		}
	}

	// Build the eBPF loader set + collector registry. Loader failures are
	// non-fatal — we degrade gracefully and surface the gap in the report
	// via a single DEGRADATION panel.
	build := buildCollectors(ctx, logger)
	defer func() {
		for _, c := range build.closers {
			c()
		}
	}()

	// Start collectors once for the lifetime of runDoctor.
	if err := build.registry.StartAll(ctx); err != nil {
		logger.Warn("one or more collectors failed to start", "error", err)
	}
	defer build.registry.StopAll()

	// Run the diagnostic loop (once, or continuous).
	for {
		if err := runDiagnosticCycle(ctx, engine, build, renderer, opts, logger); err != nil {
			return err
		}

		if !opts.continuous {
			break
		}

		logger.Debug("waiting for next cycle", "interval", opts.interval)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.interval):
		}
	}

	return nil
}

// noopCloser satisfies io.Closer with a no-op Close. Used by collectors
// that don't load any eBPF program (e.g. the procfs-based memory
// collector) so the registration table can stay uniform.
type noopCloser struct{}

func (noopCloser) Close() error { return nil }

// collectorBuildResult bundles everything runDoctor needs from the
// collector setup so it can also surface load failures in the report.
type collectorBuildResult struct {
	registry *collector.Registry
	closers  []func()
	loaded   int
	total    int
	failures []doctor.LoadFailure
}

// buildCollectors loads all enabled eBPF programs and registers a
// matching live collector for each. Loaders that fail to load are
// skipped (graceful degradation) but their errors are captured into
// the result so the doctor's pretty renderer can show a single
// DEGRADATION panel instead of letting WARN logs scatter through.
func buildCollectors(ctx context.Context, logger *slog.Logger) collectorBuildResult {
	registry := collector.NewRegistry(logger)
	// Up to 8 collectors are registered (6 eBPF + procfs memory + cgroup memory).
	closers := make([]func(), 0, 8)

	type loaderRegistration struct {
		name    string
		enabled bool
		// build creates the loader, calls Load() on it, and returns a
		// Collector ready to be registered. On Load() failure, returns
		// (nil, nil, error) so the caller can log + skip.
		build func() (collector.Collector, io.Closer, error)
	}

	// Captured so we can inject a pod enricher after the registration loop.
	var cgroupColl *collector.CgroupMemoryCollector

	registrations := []loaderRegistration{
		{
			name:    "syscall_latency",
			enabled: cfg.Collectors.SyscallLatency,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewSyscallLatencyLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewSyscallCollector(logger, l), closer, nil
			},
		},
		{
			name:    "tcp_monitor",
			enabled: cfg.Collectors.TCPMonitor,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewTCPMonitorLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewTCPCollector(logger, l), closer, nil
			},
		},
		{
			name:    "oom_track",
			enabled: cfg.Collectors.OOMTrack,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewOOMTrackLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewOOMCollector(logger, l), closer, nil
			},
		},
		{
			name:    "disk_io",
			enabled: cfg.Collectors.DiskIO,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewDiskIOLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewDiskIOCollector(logger, l), closer, nil
			},
		},
		{
			name:    "sched_delay",
			enabled: cfg.Collectors.SchedDelay,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewSchedDelayLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewSchedCollector(logger, l), closer, nil
			},
		},
		{
			name:    "fd_track",
			enabled: cfg.Collectors.FDTrack,
			build: func() (collector.Collector, io.Closer, error) {
				l := bpf.NewFDTrackLoader(logger)
				closer, err := l.Load()
				if err != nil {
					return nil, nil, err
				}
				return collector.NewFDCollector(logger, l), closer, nil
			},
		},
		{
			// Memory collector polls /proc/meminfo — it doesn't load
			// any eBPF program, so the build closure returns a no-op
			// io.Closer.
			name:    "memory",
			enabled: true,
			build: func() (collector.Collector, io.Closer, error) {
				return collector.NewMemoryCollector(logger, 0), noopCloser{}, nil
			},
		},
		{
			// Cgroup memory collector walks /sys/fs/cgroup for per-container
			// limits. Also no eBPF; root overrideable via KERNO_CGROUP_ROOT.
			name:    "cgroup_memory",
			enabled: true,
			build: func() (collector.Collector, io.Closer, error) {
				cgroupColl = collector.NewCgroupMemoryCollector(logger, 0)
				return cgroupColl, noopCloser{}, nil
			},
		},
	}

	loaded, total := 0, 0
	var failures []doctor.LoadFailure
	for _, r := range registrations {
		if !r.enabled {
			continue
		}
		total++
		coll, closer, err := r.build()
		if err != nil {
			// Log at DEBUG — the aggregate panel rendered later is the
			// user-visible signal. Operators who want raw per-program
			// errors can run with --log-level=debug.
			logger.Debug("failed to load eBPF program; collector disabled",
				"program", r.name, "error", err)
			failures = append(failures, doctor.LoadFailure{
				Program: r.name,
				Error:   err.Error(),
				Hint:    classifyLoadError(err),
			})
			continue
		}
		closers = append(closers, func() { _ = closer.Close() })
		if err := registry.Register(coll); err != nil {
			logger.Debug("failed to register collector", "name", coll.Name(), "error", err)
			failures = append(failures, doctor.LoadFailure{
				Program: coll.Name(),
				Error:   err.Error(),
				Hint:    "internal: collector registration conflict",
			})
			continue
		}
		loaded++
	}

	// Wire Kubernetes pod/namespace enrichment into the cgroup collector.
	// The adapter queries the local Kubelet API; on non-K8s nodes its index
	// stays empty and LookupByPath returns ("", "") — a no-op.
	if cgroupColl != nil {
		kubeAdapter := adapter.NewKubernetesAdapter(logger)
		// Start in a goroutine so a slow or absent Kubelet does not block
		// the doctor startup. Enrichment is best-effort: early polls may
		// have empty namespace; later polls will have it once the index is built.
		go func() { _ = kubeAdapter.Start(ctx) }() //nolint:errcheck // Start always returns nil
		cgroupColl.SetEnricher(kubeAdapter)
		closers = append(closers, func() { kubeAdapter.Stop() })
	}

	return collectorBuildResult{
		registry: registry,
		closers:  closers,
		loaded:   loaded,
		total:    total,
		failures: failures,
	}
}

// classifyLoadError maps known eBPF load error patterns to a one-line
// "what to fix" hint. Returns "" if no specific recipe matches.
func classifyLoadError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied"):
		return "re-run with sudo, or grant CAP_BPF + CAP_PERFMON to the binary"
	case strings.Contains(msg, "memlock"):
		return "increase memlock rlimit (ulimit -l unlimited) or run as root"
	case strings.Contains(msg, "btf") || strings.Contains(msg, "vmlinux"):
		return "kernel needs CONFIG_DEBUG_INFO_BTF (kernel >= 5.8 with BTF)"
	case strings.Contains(msg, "verifier") || strings.Contains(msg, "load program"):
		return "kernel verifier rejected the program — file an issue with kernel version"
	case strings.Contains(msg, "no such file") && strings.Contains(msg, "tracepoint"):
		return "this kernel may lack the required tracepoint — try a newer kernel"
	default:
		return ""
	}
}

// buildAnalyzer constructs the AI analyzer from configuration.
func buildAnalyzer(c *config.Config, logger *slog.Logger) (doctor.Analyzer, error) {
	aiCfg := c.AI

	// Build the LLM provider.
	provider, err := ai.NewProvider(ai.ProviderConfig{
		Name:        aiCfg.Provider,
		Model:       aiCfg.Model,
		APIKey:      aiCfg.APIKey,
		Endpoint:    aiCfg.Endpoint,
		MaxTokens:   aiCfg.MaxTokens,
		Temperature: aiCfg.Temperature,
	})
	if err != nil {
		return nil, fmt.Errorf("creating AI provider: %w", err)
	}

	// Wrap with rate limiter.
	if aiCfg.RateLimitPerMinute > 0 {
		provider = ai.NewRateLimitedProvider(provider, aiCfg.RateLimitPerMinute)
	}

	// Build the cache.
	var cache *ai.Cache
	if aiCfg.CacheTTL != "" {
		ttl, err := time.ParseDuration(aiCfg.CacheTTL)
		if err != nil {
			logger.Warn("invalid ai.cache_ttl, using 5m default", "value", aiCfg.CacheTTL, "error", err)
			ttl = 5 * time.Minute
		}
		cache = ai.NewCache(ttl)
	}

	// Resolve privacy mode.
	privacy := ai.PrivacyMode(aiCfg.PrivacyMode)
	if privacy == "" {
		privacy = ai.PrivacySummary
	}

	return ai.NewAnalyzer(ai.AnalyzerConfig{
		Provider: provider,
		Cache:    cache,
		Privacy:  privacy,
		Logger:   logger,
	}), nil
}

func runDiagnosticCycle(
	ctx context.Context,
	engine *doctor.Engine,
	build collectorBuildResult,
	renderer doctor.Renderer,
	opts doctorOpts,
	logger *slog.Logger,
) error {
	registry := build.registry
	logger.Debug("starting kernel diagnostic",
		"duration", opts.duration,
		"ai", opts.aiEnabled,
	)

	// Phase 1: Start collectors and let them consume events for the
	// configured duration. Each collector runs its own goroutine driven
	// by the loader's ringbuf; we just bound the lifetime here.
	collectCtx, cancel := context.WithTimeout(ctx, opts.duration)
	defer cancel()

	// Live progress spinner — only when stdout is going to pretty
	// output AND stderr is a TTY. JSON output, piped output, and CI
	// runs (NO_COLOR) get a single-line status instead.
	showSpinner := opts.output != "json" && isTerminal()
	if opts.output != "json" {
		if showSpinner {
			spinner := NewSpinner(os.Stderr, os.Getenv("NO_COLOR") != "")
			spinner.SetPhase("collecting kernel signals")
			spinner.SetEventsFn(func() uint64 {
				snap := registry.Signals(opts.duration)
				var n uint64
				if snap.Syscall != nil {
					n += snap.Syscall.TotalCount
				}
				if snap.Sched != nil {
					n += snap.Sched.TotalCount
				}
				if snap.OOM != nil && snap.OOM.Count > 0 {
					n += uint64(snap.OOM.Count) //nolint:gosec // Count is a slice len; non-negative
				}
				if snap.DiskIO != nil {
					n += snap.DiskIO.TotalReads + snap.DiskIO.TotalWrites + snap.DiskIO.TotalSyncs
				}
				if snap.FD != nil {
					n += snap.FD.TotalOpens + snap.FD.TotalCloses
				}
				return n
			})
			go spinner.Run(collectCtx, opts.duration)
			defer spinner.Stop()
		} else {
			fmt.Fprintf(os.Stderr, "Collecting kernel signals for %s...\n", opts.duration)
		}
	}

	// Wait for collection window to complete.
	<-collectCtx.Done()

	// Check if we were canceled by the parent context (Ctrl+C) vs timeout.
	if ctx.Err() != nil {
		if opts.output != "json" {
			fmt.Fprintf(os.Stderr, "\nInterrupted — analyzing partial data.\n")
		}
	}

	// Phase 2: Gather combined signal snapshot from all collectors.
	signals := registry.Signals(opts.duration)

	// Phase 3: Run diagnostic engine (rules + optional AI).
	report, err := engine.Diagnose(ctx, signals)
	if err != nil {
		return fmt.Errorf("diagnosis failed: %w", err)
	}

	// Annotate the report with deployment context (k8s pod, systemd
	// unit, baremetal hostname) and any eBPF load failures so the
	// renderer can show a single DEGRADATION panel rather than letting
	// raw WARN logs scatter through stderr.
	report.Environment = string(adapter.DetectEnvironment())
	report.LoadFailures = build.failures
	report.ProgramsLoaded = build.loaded

	// phase 3b: apply only-critical filter
	// happens after rule evaluation but before rendering.
	if opts.onlyCritical {
		report.Findings = doctor.FilterCriticalFindings(report.Findings)
	}

	// Phase 4: Render the report.
	//
	// In --quiet mode, we suppress the full pretty rendering when the
	// system is healthy (only critical/warning findings warrant
	// output). JSON mode is unaffected — machine consumers expect a
	// stable shape every time.
	if opts.quiet && opts.output != "json" {
		hasIssues := false
		for i := range report.Findings {
			if report.Findings[i].Severity >= doctor.SeverityWarning {
				hasIssues = true
				break
			}
		}
		if !hasIssues {
			// Single-line "all clear" — CI-friendly.
			fmt.Fprintf(os.Stdout, "kerno: ✓ all kernel signals nominal (%s window, %d events)\n",
				opts.duration, report.EventsCollected)
		} else if err := renderer.Render(os.Stdout, report); err != nil {
			return fmt.Errorf("rendering report: %w", err)
		}
	} else if err := renderer.Render(os.Stdout, report); err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}

	// Phase 5: Exit code handling for CI/CD.
	// with only-critical, only exit 1 if critical items remain after filtering
	if opts.exitCode && report.HasCritical() {
		return &exitError{code: 1}
	}

	return nil
}

// exitError is returned when --exit-code is set and critical findings exist.
type exitError struct {
	code int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("critical findings detected (exit code %d)", e.code)
}

// ExitCode returns the exit code for this error.
func (e *exitError) ExitCode() int {
	return e.code
}
